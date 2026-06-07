package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	"github.com/aymanbagabas/go-osc52/v2"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	injectcore "github.com/emqmalte/bolty/internal/inject"
	"github.com/emqmalte/bolty/internal/passbolt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

type folderResourceLoader func(context.Context, string) ([]passbolt.ResourceSummary, error)
type globalResourceSearcher func(context.Context, string) ([]passbolt.ResourceSummary, error)
type resourceDetailLoader func(context.Context, string) (passbolt.DecryptedResource, error)
type placeholderCopier func(string) error
type webOpener func(string) error

type browserView int

const (
	resourceBrowserView browserView = iota
	fieldBrowserView
	descriptionBrowserView
)

type searchMode int

const (
	localSearchMode searchMode = iota
	globalSearchMode
)

type browserEntry struct {
	resource passbolt.ResourceSummary
}

type browserPane int

const (
	folderPane browserPane = iota
	resourcePane
)

type folderTreeRow struct {
	ID    string
	Label string
}

type resourceLoadedMsg struct {
	resource passbolt.DecryptedResource
	err      error
}

type directoryLoadedMsg struct {
	folderID string
	items    []passbolt.ResourceSummary
	err      error
}

type globalSearchMsg struct {
	query string
	items []passbolt.ResourceSummary
	err   error
}

type placeholderCopiedMsg struct {
	placeholder string
	err         error
}

type fieldValueCopiedMsg struct {
	label string
	err   error
}

type totpTickMsg time.Time

type webOpenedMsg struct {
	err error
}

type resourceBrowserModel struct {
	ctx          context.Context
	view         browserView
	mode         searchMode
	pane         browserPane
	folderTree   table.Model
	resources    table.Model
	fields       table.Model
	description  viewport.Model
	search       textinput.Model
	folders      []passbolt.FolderSummary
	folderRows   []folderTreeRow
	folderByID   map[string]passbolt.FolderSummary
	currentDir   string
	cache        map[string][]passbolt.ResourceSummary
	entries      []browserEntry
	filtered     []browserEntry
	globalReturn string
	loadFolder   folderResourceLoader
	searchAll    globalResourceSearcher
	loadResource resourceDetailLoader
	copy         placeholderCopier
	open         webOpener
	serverURL    string
	resource     passbolt.DecryptedResource
	totp         injectcore.TOTPStatus
	hasTOTP      bool
	reveal       bool
	loading      bool
	status       string
	width        int
	height       int
	fieldCols    int
	resourceDefs []table.Column
	folderWidth  int
}

func newResourceBrowserModel(
	ctx context.Context,
	folders []passbolt.FolderSummary,
	serverURL string,
	loadFolder folderResourceLoader,
	searchAll globalResourceSearcher,
	loadResource resourceDetailLoader,
	copy placeholderCopier,
	open webOpener,
) resourceBrowserModel {
	search := textinput.New()
	search.Prompt = "Filter: "
	search.Placeholder = "filter loaded items"
	search.CharLimit = 128

	resourceColumns := resourceTableColumns(80)
	resources := table.New(
		table.WithColumns(resourceColumns),
		table.WithWidth(80),
		table.WithHeight(17),
		table.WithFocused(true),
	)
	resources.SetStyles(browserTableStyles())
	folderRows := buildFolderTreeRows(folders)
	folderTree := table.New(
		table.WithColumns([]table.Column{{Title: "Folders", Width: 28}}),
		table.WithRows(folderTableRows(folderRows)),
		table.WithWidth(30),
		table.WithHeight(17),
		table.WithFocused(true),
	)
	folderTree.SetStyles(browserTableStyles())
	resources.Blur()

	fieldColumns := fieldTableColumns(80)
	fields := table.New(
		table.WithColumns(fieldColumns),
		table.WithWidth(80),
		table.WithHeight(17),
		table.WithFocused(true),
	)
	fields.SetStyles(browserTableStyles())
	description := viewport.New(80, 17)

	folderByID := make(map[string]passbolt.FolderSummary, len(folders))
	for _, folder := range folders {
		folderByID[folder.ID] = folder
	}
	return resourceBrowserModel{
		ctx:          ctx,
		pane:         folderPane,
		folderTree:   folderTree,
		resources:    resources,
		fields:       fields,
		description:  description,
		search:       search,
		folders:      folders,
		folderRows:   folderRows,
		folderByID:   folderByID,
		cache:        map[string][]passbolt.ResourceSummary{},
		loading:      true,
		loadFolder:   loadFolder,
		searchAll:    searchAll,
		loadResource: loadResource,
		copy:         copy,
		open:         open,
		serverURL:    strings.TrimRight(serverURL, "/"),
		fieldCols:    len(fieldColumns),
		resourceDefs: resourceColumns,
	}
}

func (m resourceBrowserModel) Init() tea.Cmd {
	return loadDirectoryCmd(m.ctx, m.loadFolder, "")
}

func (m resourceBrowserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
	case tea.KeyMsg:
		if m.search.Focused() {
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.search.Blur()
				m.search.SetValue("")
				m.mode = localSearchMode
				m.applyLocalFilter()
				return m, nil
			case "enter":
				if m.mode == globalSearchMode {
					query := strings.TrimSpace(m.search.Value())
					if query == "" {
						m.status = "Enter a global search term"
						return m, nil
					}
					m.search.Blur()
					m.loading = true
					m.status = "Searching all Passbolt resources..."
					return m, globalSearchCmd(m.ctx, m.searchAll, query)
				}
				m.search.Blur()
				return m, nil
			}
		} else {
			switch msg.String() {
			case "ctrl+c", "q":
				return m, tea.Quit
			case "/":
				if m.view == resourceBrowserView && !m.loading {
					m.pane = resourcePane
					m.syncPaneFocus()
					m.mode = localSearchMode
					m.search.Prompt = "Filter: "
					m.search.Placeholder = "filter loaded items"
					m.search.Focus()
					return m, textinput.Blink
				}
			case "g":
				if m.view == resourceBrowserView && !m.loading {
					m.pane = resourcePane
					m.syncPaneFocus()
					m.mode = globalSearchMode
					m.search.Prompt = "Global: "
					m.search.Placeholder = "downloads and searches all resources"
					m.search.SetValue("")
					m.search.Focus()
					return m, textinput.Blink
				}
			case "tab", "shift+tab":
				if m.view == resourceBrowserView {
					m.togglePane()
					return m, nil
				}
			case "left":
				if m.view == resourceBrowserView {
					m.pane = folderPane
					m.syncPaneFocus()
					return m, nil
				}
				fallthrough
			case "esc", "backspace", "u":
				if m.view == descriptionBrowserView {
					m.view = fieldBrowserView
					return m, nil
				}
				if m.view == fieldBrowserView {
					m.view = resourceBrowserView
					m.resource = passbolt.DecryptedResource{}
					m.reveal = false
					return m, nil
				}
				if m.globalReturn != "" || strings.HasPrefix(m.status, "Global results") {
					return m.restoreDirectory()
				}
			case "right":
				if m.view == resourceBrowserView {
					m.pane = resourcePane
					m.syncPaneFocus()
					return m, nil
				}
				fallthrough
			case "enter":
				if m.loading {
					return m, nil
				}
				if m.view == resourceBrowserView {
					if m.pane == folderPane {
						return m.openSelectedFolder()
					}
					entry, ok := m.selectedEntry()
					if !ok {
						return m, nil
					}
					m.loading = true
					m.status = "Loading resource details..."
					return m, loadResourceCmd(m.ctx, m.loadResource, entry.resource.ID)
				}
				if m.view == fieldBrowserView {
					return m.copySelectedField()
				}
			case "c":
				if m.view == fieldBrowserView {
					return m.copySelectedFieldValue()
				}
			case "d":
				if m.view == descriptionBrowserView {
					m.view = fieldBrowserView
					return m, nil
				}
				if m.view == fieldBrowserView {
					if strings.TrimSpace(m.resourceDescription()) == "" {
						m.status = "This resource has no description"
						return m, nil
					}
					m.description.GotoTop()
					m.view = descriptionBrowserView
					return m, nil
				}
			case "r":
				if m.view == fieldBrowserView {
					m.reveal = !m.reveal
					m.refreshTOTPStatus(time.Now())
					m.refreshFieldRows(false)
					return m, nil
				}
			case "o":
				target, ok := m.selectedWebURL()
				if ok {
					m.status = "Opening " + target
					return m, openWebCmd(m.open, target)
				}
			}
		}
	case directoryLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.status = "Could not load folder: " + msg.err.Error()
			return m, nil
		}
		m.cache[msg.folderID] = msg.items
		m.currentDir = msg.folderID
		m.globalReturn = ""
		m.status = ""
		m.search.SetValue("")
		m.rebuildDirectoryEntries()
		m.selectFolder(msg.folderID)
		return m, nil
	case globalSearchMsg:
		m.loading = false
		if msg.err != nil {
			m.status = "Global search failed: " + msg.err.Error()
			return m, nil
		}
		m.globalReturn = m.currentDir
		m.pane = resourcePane
		m.syncPaneFocus()
		m.entries = resourceEntries(msg.items)
		m.filtered = append([]browserEntry(nil), m.entries...)
		m.resources.SetRows(resourceTableRows(m.filtered, m.resourceDefs))
		m.resources.SetCursor(0)
		m.status = fmt.Sprintf("Global results for %q. Esc returns to %s.", msg.query, m.currentPath())
		return m, nil
	case resourceLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.status = "Could not load resource: " + msg.err.Error()
			return m, nil
		}
		m.resource = msg.resource
		m.reveal = false
		m.refreshTOTPStatus(time.Now())
		m.status = ""
		m.view = fieldBrowserView
		m.refreshDescription()
		m.refreshFieldRows(true)
		if m.hasTOTP {
			return m, totpTickCmd(time.Now())
		}
		return m, nil
	case totpTickMsg:
		if m.view == fieldBrowserView {
			now := time.Time(msg)
			if m.hasTOTP && !now.Before(m.totp.ExpiresAt) {
				m.refreshTOTPStatus(now)
			}
			m.refreshTOTPRow(now)
			if m.hasTOTP {
				return m, totpTickCmd(now)
			}
			return m, nil
		}
		if m.view == descriptionBrowserView && m.hasTOTP {
			return m, totpTickCmd(time.Time(msg))
		}
		return m, nil
	case placeholderCopiedMsg:
		if msg.err != nil {
			m.status = "Could not copy reference: " + msg.err.Error()
		} else {
			m.status = "Copied " + msg.placeholder
		}
		return m, nil
	case fieldValueCopiedMsg:
		if msg.err != nil {
			m.status = "Could not copy value: " + msg.err.Error()
		} else {
			m.status = "Copied value of " + msg.label
		}
		return m, nil
	case webOpenedMsg:
		if msg.err != nil {
			m.status = "Could not open Passbolt: " + msg.err.Error()
		} else {
			m.status = "Opened in Passbolt"
		}
		return m, nil
	}

	if m.search.Focused() {
		before := m.search.Value()
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		if m.mode == localSearchMode && m.search.Value() != before {
			m.applyLocalFilter()
		}
		return m, cmd
	}
	var cmd tea.Cmd
	if m.view == descriptionBrowserView {
		m.description, cmd = m.description.Update(msg)
	} else if m.view == fieldBrowserView {
		m.fields, cmd = m.fields.Update(msg)
	} else {
		if m.pane == folderPane {
			m.folderTree, cmd = m.folderTree.Update(msg)
		} else {
			m.resources, cmd = m.resources.Update(msg)
		}
	}
	return m, cmd
}

func (m resourceBrowserModel) View() string {
	if m.view == descriptionBrowserView {
		return m.descriptionView()
	}
	if m.view == fieldBrowserView {
		return m.fieldView()
	}
	title := titleStyle().Render("Passbolt")
	location := labeledDetail("Location", m.currentPath())
	count := fmt.Sprintf("%d item", len(m.filtered))
	if len(m.filtered) != 1 {
		count += "s"
	}
	header := title + "  " + location + "  " + faintStyle().Render(count)
	help := faintStyle().Render("tab/←/→ switch pane  enter select/open  / filter  g global search  o web  q quit")
	parts := []string{header, m.search.View(), m.splitPaneView(), m.selectedEntryDetail()}
	if m.status != "" {
		parts = append(parts, statusStyle().Render(safeDisplayText(m.status)))
	}
	return strings.Join(append(parts, help), "\n")
}

func (m resourceBrowserModel) fieldView() string {
	name := resourceDisplayName(m.resource)
	header := titleStyle().Render(name) + "  " + faintStyle().Render(m.resource.ID)
	summary := labeledDetail("Username", valueOrDash(metadataString(m.resource.Metadata, "username")))
	description := labeledDetail("Description", descriptionPreview(m.resourceDescription(), m.contentWidth(), true))
	uriSummary := resourceURISummary(passbolt.ResourceURIs(m.resource.Metadata, m.resource.Secrets))
	help := faintStyle().Render("enter copy reference  c copy value  d full description  r reveal/hide  o web  esc back  q quit")
	parts := []string{header, summary, description, uriSummary, m.fields.View()}
	if m.status != "" {
		parts = append(parts, statusStyle().Render(safeDisplayText(m.status)))
	}
	return strings.Join(append(parts, help), "\n")
}

func (m resourceBrowserModel) descriptionView() string {
	header := titleStyle().Render(resourceDisplayName(m.resource)) + "  " + faintStyle().Render("Description")
	position := fmt.Sprintf("%3.0f%%", m.description.ScrollPercent()*100)
	help := faintStyle().Render("↑/↓ scroll  pgup/pgdn page  d/esc back  q quit")
	return strings.Join([]string{header, m.description.View(), position + "  " + help}, "\n")
}

func (m resourceBrowserModel) openDirectory(id string) (tea.Model, tea.Cmd) {
	if _, ok := m.cache[id]; ok {
		m.currentDir = id
		m.globalReturn = ""
		m.status = ""
		m.search.SetValue("")
		m.rebuildDirectoryEntries()
		return m, nil
	}
	m.loading = true
	m.status = "Loading " + m.pathFor(id) + "..."
	return m, loadDirectoryCmd(m.ctx, m.loadFolder, id)
}

func (m resourceBrowserModel) restoreDirectory() (tea.Model, tea.Cmd) {
	m.currentDir = m.globalReturn
	m.globalReturn = ""
	m.status = ""
	m.search.SetValue("")
	m.rebuildDirectoryEntries()
	return m, nil
}

func (m *resourceBrowserModel) rebuildDirectoryEntries() {
	entries := resourceEntries(m.cache[m.currentDir])
	m.entries = entries
	m.filtered = append([]browserEntry(nil), entries...)
	m.resources.SetRows(resourceTableRows(m.filtered, m.resourceDefs))
	m.resources.SetCursor(0)
}

func buildFolderTreeRows(folders []passbolt.FolderSummary) []folderTreeRow {
	children := map[string][]passbolt.FolderSummary{}
	for _, folder := range folders {
		children[folder.ParentID] = append(children[folder.ParentID], folder)
	}
	for parentID := range children {
		sort.Slice(children[parentID], func(i, j int) bool {
			return strings.ToLower(children[parentID][i].Name) < strings.ToLower(children[parentID][j].Name)
		})
	}

	rows := []folderTreeRow{{ID: "", Label: "Root"}}
	seen := map[string]struct{}{}
	var appendChildren func(string, int)
	appendChildren = func(parentID string, depth int) {
		items := children[parentID]
		for i, folder := range items {
			if _, exists := seen[folder.ID]; exists {
				continue
			}
			seen[folder.ID] = struct{}{}
			branch := "├─ "
			if i == len(items)-1 {
				branch = "└─ "
			}
			rows = append(rows, folderTreeRow{
				ID:    folder.ID,
				Label: strings.Repeat("  ", depth) + branch + valueOrDash(folder.Name),
			})
			appendChildren(folder.ID, depth+1)
		}
	}
	appendChildren("", 0)
	return rows
}

func folderTableRows(rows []folderTreeRow) []table.Row {
	result := make([]table.Row, len(rows))
	for i, row := range rows {
		result[i] = table.Row{safeTreeText(row.Label)}
	}
	return result
}

func (m *resourceBrowserModel) togglePane() {
	if m.pane == folderPane {
		m.pane = resourcePane
	} else {
		m.pane = folderPane
	}
	m.syncPaneFocus()
}

func (m *resourceBrowserModel) syncPaneFocus() {
	if m.pane == folderPane {
		m.folderTree.Focus()
		m.resources.Blur()
	} else {
		m.folderTree.Blur()
		m.resources.Focus()
	}
}

func (m resourceBrowserModel) selectedFolderID() (string, bool) {
	index := m.folderTree.Cursor()
	if index < 0 || index >= len(m.folderRows) {
		return "", false
	}
	return m.folderRows[index].ID, true
}

func (m resourceBrowserModel) openSelectedFolder() (tea.Model, tea.Cmd) {
	id, ok := m.selectedFolderID()
	if !ok {
		return m, nil
	}
	return m.openDirectory(id)
}

func (m *resourceBrowserModel) selectFolder(id string) {
	for i, row := range m.folderRows {
		if row.ID == id {
			m.folderTree.SetCursor(i)
			return
		}
	}
}

func (m resourceBrowserModel) splitPaneView() string {
	leftWidth := m.folderWidth
	if leftWidth <= 0 {
		leftWidth = 30
	}
	rightWidth := max(m.width-leftWidth, 16)
	leftTitle := "Folders"
	rightTitle := "Secrets"
	if m.pane == folderPane {
		leftTitle = "Folders •"
	} else {
		rightTitle = "Secrets •"
	}
	left := paneStyle(m.pane == folderPane, leftWidth).Render(titleStyle().Render(leftTitle) + "\n" + m.folderTree.View())
	right := paneStyle(m.pane == resourcePane, rightWidth).Render(titleStyle().Render(rightTitle) + "\n" + m.resources.View())
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func paneStyle(focused bool, width int) lipgloss.Style {
	color := lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#4B5563"}
	if focused {
		color = lipgloss.AdaptiveColor{Light: "#7C3AED", Dark: "#C084FC"}
	}
	return lipgloss.NewStyle().
		Width(max(width-4, 10)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(color).
		Padding(0, 1)
}

func resourceEntries(resources []passbolt.ResourceSummary) []browserEntry {
	entries := make([]browserEntry, 0, len(resources))
	for _, resource := range resources {
		entries = append(entries, browserEntry{resource: resource})
	}
	return entries
}

func (m *resourceBrowserModel) applyLocalFilter() {
	query := strings.TrimSpace(m.search.Value())
	if query == "" {
		m.filtered = append(m.filtered[:0], m.entries...)
	} else {
		targets := make([]string, len(m.entries))
		for i, entry := range m.entries {
			targets[i] = entryFilterValue(entry)
		}
		ranks := list.DefaultFilter(query, targets)
		m.filtered = make([]browserEntry, 0, len(ranks))
		for _, rank := range ranks {
			m.filtered = append(m.filtered, m.entries[rank.Index])
		}
	}
	m.resources.SetRows(resourceTableRows(m.filtered, m.resourceDefs))
	m.resources.SetCursor(0)
}

func entryFilterValue(entry browserEntry) string {
	r := entry.resource
	values := []string{r.Name, r.Username, r.URI, r.Description, r.FolderPath, r.ID, r.ResourceType}
	values = append(values, r.URIs...)
	return strings.Join(values, " ")
}

func resourceTableColumns(width int) []table.Column {
	switch {
	case width < 52:
		return []table.Column{{Title: "Name", Width: max(width-4, 12)}}
	case width < 72:
		return []table.Column{{Title: "Type", Width: 8}, {Title: "Name", Width: max(width-14, 18)}}
	case width < 100:
		return []table.Column{{Title: "Type", Width: 8}, {Title: "Name", Width: 28}, {Title: "Username", Width: max(width-44, 16)}}
	default:
		return []table.Column{{Title: "Type", Width: 8}, {Title: "Name", Width: 30}, {Title: "Username", Width: 20}, {Title: "URI", Width: max(width-66, 24)}}
	}
}

func resourceTableRows(entries []browserEntry, columns []table.Column) []table.Row {
	rows := make([]table.Row, 0, len(entries))
	for _, entry := range entries {
		row := make(table.Row, 0, len(columns))
		for _, column := range columns {
			switch column.Title {
			case "Type":
				row = append(row, "Secret")
			case "Name":
				row = append(row, safeDisplayText(entry.resource.Name))
			case "Username":
				row = append(row, safeDisplayText(entry.resource.Username))
			case "URI":
				row = append(row, safeDisplayText(entry.resource.URI))
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func fieldTableColumns(width int) []table.Column {
	if width < 64 {
		return []table.Column{{Title: "Field", Width: max(width/3, 12)}, {Title: "Value", Width: max(width-width/3-6, 20)}}
	}
	return []table.Column{{Title: "Field", Width: 20}, {Title: "Value", Width: max(width-50, 20)}, {Title: "Inject selector", Width: 24}}
}

func (m *resourceBrowserModel) refreshFieldRows(resetCursor bool) {
	fields := injectcore.AvailableFields(m.resource)
	rows := make([]table.Row, 0, len(fields))
	for _, field := range fields {
		value := ""
		if field.Selector == string(injectcore.FieldTOTP) && m.hasTOTP {
			value = formatTOTPValue(m.totp, m.reveal, time.Now())
		} else {
			var err error
			value, err = injectcore.FieldValue(m.resource, field.Selector)
			if err != nil {
				value = "<unavailable>"
			} else if !m.reveal && isSensitiveSelector(field.Selector) {
				value = maskedSecretValue()
			}
		}
		values := table.Row{field.Label, safeDisplayText(value), field.Selector}
		if field.Selector == string(injectcore.FieldTOTP) {
			values[1] = value
		}
		rows = append(rows, values[:min(m.fieldCols, len(values))])
	}
	m.fields.SetRows(rows)
	if resetCursor {
		m.fields.SetCursor(0)
	}
}

func (m *resourceBrowserModel) refreshTOTPRow(now time.Time) {
	fields := injectcore.AvailableFields(m.resource)
	rows := append([]table.Row(nil), m.fields.Rows()...)
	if len(rows) != len(fields) {
		return
	}

	for i, field := range fields {
		if field.Selector != string(injectcore.FieldTOTP) {
			continue
		}
		var value string
		if !m.hasTOTP {
			value = "<unavailable>"
		} else {
			value = formatTOTPValue(m.totp, m.reveal, now)
		}
		values := table.Row{field.Label, safeDisplayText(value), field.Selector}
		values[1] = value
		rows[i] = values[:min(m.fieldCols, len(values))]
		m.fields.SetRows(rows)
		return
	}
}

func (m *resourceBrowserModel) refreshTOTPStatus(now time.Time) {
	if m.reveal {
		m.totp, m.hasTOTP = injectcore.TOTPStatusAt(m.resource, now)
		return
	}
	m.totp, m.hasTOTP = injectcore.TOTPInfoAt(m.resource, now)
}

func maskedSecretValue() string {
	return strings.Repeat("•", 8)
}

func formatTOTPValue(status injectcore.TOTPStatus, reveal bool, now time.Time) string {
	token := maskedSecretValue()
	if reveal && status.Code != "" {
		token = status.Code + strings.Repeat(" ", max(8-len(status.Code), 0))
	}
	return token + totpExpiryIndicator(status, now)
}

func totpExpiryIndicator(status injectcore.TOTPStatus, now time.Time) string {
	if status.Period <= 0 || status.ExpiresAt.IsZero() {
		return ""
	}
	remaining := status.ExpiresAt.Sub(now)
	if remaining < 0 {
		remaining = 0
	}
	seconds := int((remaining + time.Second - 1) / time.Second)
	fraction := float64(remaining) / float64(status.Period)
	filled := min(max(int(fraction*8+0.5), 0), 8)
	periodSeconds := int((status.Period + time.Second - 1) / time.Second)
	countdownWidth := max(len(strconv.Itoa(periodSeconds)), 2)
	return fmt.Sprintf("  %*ds [%s%s]", countdownWidth, seconds, strings.Repeat("●", filled), strings.Repeat("○", 8-filled))
}

func isSensitiveSelector(selector string) bool {
	return selector == "password" || selector == "totp" || strings.HasPrefix(selector, "custom/")
}

func (m resourceBrowserModel) copySelectedField() (tea.Model, tea.Cmd) {
	fields := injectcore.AvailableFields(m.resource)
	index := m.fields.Cursor()
	if index < 0 || index >= len(fields) {
		return m, nil
	}
	placeholder, err := injectcore.BuildPlaceholder(m.resource.ID, fields[index].Selector)
	if err != nil {
		m.status = "Could not build reference: " + err.Error()
		return m, nil
	}
	return m, copyPlaceholderCmd(m.copy, placeholder)
}

func (m resourceBrowserModel) copySelectedFieldValue() (tea.Model, tea.Cmd) {
	fields := injectcore.AvailableFields(m.resource)
	index := m.fields.Cursor()
	if index < 0 || index >= len(fields) {
		return m, nil
	}
	field := fields[index]
	value, err := injectcore.FieldValue(m.resource, field.Selector)
	if err != nil {
		m.status = "Could not read value: " + err.Error()
		return m, nil
	}
	return m, copyFieldValueCmd(m.copy, field.Label, value)
}

func (m resourceBrowserModel) selectedEntry() (browserEntry, bool) {
	index := m.resources.Cursor()
	if index < 0 || index >= len(m.filtered) {
		return browserEntry{}, false
	}
	return m.filtered[index], true
}

func (m resourceBrowserModel) selectedEntryDetail() string {
	if m.pane == folderPane {
		id, ok := m.selectedFolderID()
		if !ok {
			return faintStyle().Render("No folder selected")
		}
		return labeledDetail("Folder", m.pathFor(id)) + "   " + labeledDetail("Resources", folderResourceCount(m.cache[id]))
	}
	entry, ok := m.selectedEntry()
	if !ok {
		return faintStyle().Render("No matching items")
	}
	r := entry.resource
	return strings.Join([]string{
		labeledDetail("Folder", valueOrRoot(r.FolderPath)),
		labeledDetail("Description", descriptionPreview(r.Description, m.contentWidth(), false)),
		labeledDetail("Type", valueOrDash(r.ResourceType)) + "   " + labeledDetail("UUID", r.ID),
	}, "\n")
}

func (m resourceBrowserModel) selectedWebURL() (string, bool) {
	if m.view != resourceBrowserView && m.resource.ID != "" {
		return m.serverURL + "/app/passwords/view/" + url.PathEscape(m.resource.ID), true
	}
	if m.pane == folderPane {
		id, ok := m.selectedFolderID()
		if !ok || id == "" {
			return "", false
		}
		return m.serverURL + "/app/folders/view/" + url.PathEscape(id), true
	}
	entry, ok := m.selectedEntry()
	if !ok {
		return "", false
	}
	return m.serverURL + "/app/passwords/view/" + url.PathEscape(entry.resource.ID), true
}

func folderResourceCount(resources []passbolt.ResourceSummary) string {
	if resources == nil {
		return "not loaded"
	}
	return strconv.Itoa(len(resources))
}

func (m resourceBrowserModel) currentPath() string { return m.pathFor(m.currentDir) }

func (m resourceBrowserModel) pathFor(id string) string {
	if id == "" {
		return "Root"
	}
	var names []string
	seen := map[string]struct{}{}
	for id != "" {
		if _, exists := seen[id]; exists {
			break
		}
		seen[id] = struct{}{}
		folder, ok := m.folderByID[id]
		if !ok {
			break
		}
		names = append(names, folder.Name)
		id = folder.ParentID
	}
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	return "Root / " + strings.Join(names, " / ")
}

func (m *resourceBrowserModel) resize() {
	totalWidth := max(m.width, 36)
	m.folderWidth = min(max(totalWidth/3, 16), 32)
	resourceWidth := max(totalWidth-m.folderWidth, 16)
	m.folderTree.SetRows(nil)
	m.folderTree.SetColumns([]table.Column{{Title: "Folder", Width: max(m.folderWidth-6, 12)}})
	m.folderTree.SetRows(folderTableRows(m.folderRows))
	m.folderTree.SetWidth(max(m.folderWidth-2, 16))
	m.folderTree.SetHeight(max(m.height-11, 5))
	resourceColumns := resourceTableColumns(resourceWidth)
	m.resourceDefs = resourceColumns
	m.resources.SetRows(nil)
	m.resources.SetColumns(resourceColumns)
	m.resources.SetRows(resourceTableRows(m.filtered, m.resourceDefs))
	m.resources.SetWidth(resourceWidth)
	m.resources.SetHeight(max(m.height-11, 5))
	fieldColumns := fieldTableColumns(m.width)
	m.fieldCols = len(fieldColumns)
	m.fields.SetRows(nil)
	m.fields.SetColumns(fieldColumns)
	m.fields.SetWidth(m.width)
	m.fields.SetHeight(max(m.height-11, 5))
	m.description.Width = max(m.width, 20)
	m.description.Height = max(m.height-3, 5)
	m.search.Width = max(m.width-len(m.search.Prompt)-2, 10)
	if m.resource.ID != "" {
		m.refreshDescription()
		m.refreshFieldRows(false)
	}
	m.syncPaneFocus()
}

func (m *resourceBrowserModel) refreshDescription() {
	description := safeMultilineText(m.resourceDescription())
	if strings.TrimSpace(description) == "" {
		description = "No description"
	}
	m.description.SetContent(lipgloss.NewStyle().Width(m.contentWidth()).Render(description))
}

func (m resourceBrowserModel) resourceDescription() string {
	value, err := injectcore.FieldValue(m.resource, string(injectcore.FieldDesc))
	if err == nil {
		return value
	}
	return metadataString(m.resource.Metadata, "description")
}

func (m resourceBrowserModel) contentWidth() int {
	width := m.width
	if width <= 0 {
		width = 80
	}
	return max(width-2, 20)
}

func loadDirectoryCmd(ctx context.Context, load folderResourceLoader, id string) tea.Cmd {
	return func() tea.Msg {
		items, err := load(ctx, id)
		return directoryLoadedMsg{folderID: id, items: items, err: err}
	}
}

func globalSearchCmd(ctx context.Context, search globalResourceSearcher, query string) tea.Cmd {
	return func() tea.Msg {
		items, err := search(ctx, query)
		return globalSearchMsg{query: query, items: items, err: err}
	}
}

func loadResourceCmd(ctx context.Context, load resourceDetailLoader, id string) tea.Cmd {
	return func() tea.Msg {
		resource, err := load(ctx, id)
		return resourceLoadedMsg{resource: resource, err: err}
	}
}

func copyPlaceholderCmd(copy placeholderCopier, placeholder string) tea.Cmd {
	return func() tea.Msg { return placeholderCopiedMsg{placeholder: placeholder, err: copy(placeholder)} }
}

func copyFieldValueCmd(copy placeholderCopier, label, value string) tea.Cmd {
	return func() tea.Msg { return fieldValueCopiedMsg{label: label, err: copy(value)} }
}

func totpTickCmd(now time.Time) tea.Cmd {
	delay := time.Second - time.Duration(now.Nanosecond())
	return tea.Tick(delay, func(now time.Time) tea.Msg {
		return totpTickMsg(now)
	})
}

func openWebCmd(open webOpener, target string) tea.Cmd {
	return func() tea.Msg { return webOpenedMsg{err: open(target)} }
}

func browserTableStyles() table.Styles {
	styles := table.DefaultStyles()
	styles.Header = styles.Header.BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).Bold(true)
	styles.Selected = styles.Selected.
		Foreground(lipgloss.AdaptiveColor{Light: "#7C3AED", Dark: "#C084FC"}).
		Background(lipgloss.AdaptiveColor{Light: "#F3E8FF", Dark: "#2E1065"}).
		Bold(true)
	return styles
}

func metadataString(metadata map[string]any, key string) string {
	if value, ok := metadata[key].(string); ok {
		return value
	}
	return ""
}

func resourceDisplayName(resource passbolt.DecryptedResource) string {
	if strings.TrimSpace(resource.DecryptedName) != "" {
		return safeDisplayText(resource.DecryptedName)
	}
	return resource.ID
}

func safeDisplayText(value string) string {
	return strings.Join(strings.FieldsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}), " ")
}

func safeTreeText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}

func safeMultilineText(value string) string {
	var builder strings.Builder
	for _, r := range strings.ReplaceAll(value, "\r\n", "\n") {
		switch {
		case r == '\n':
			builder.WriteRune(r)
		case r == '\t':
			builder.WriteString("    ")
		case unicode.IsControl(r):
			builder.WriteRune(' ')
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func descriptionPreview(value string, width int, canOpen bool) string {
	value = safeDisplayText(value)
	if value == "" {
		return "-"
	}
	limit := max(width-18, 24)
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	marker := "[truncated]"
	if canOpen {
		marker = "[truncated; press d]"
	}
	return strings.TrimSpace(string(runes[:limit-1])) + "… " + marker
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func valueOrRoot(value string) string {
	if strings.TrimSpace(value) == "" {
		return "Root"
	}
	return value
}

func labeledDetail(label, value string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#5B21B6", Dark: "#C084FC"}).Render(label+":") + " " + safeDisplayText(value)
}

func resourceURISummary(uris []string) string {
	if len(uris) == 0 {
		return labeledDetail("URIs", "-")
	}
	lines := make([]string, 0, len(uris)+1)
	lines = append(lines, labeledDetail("URIs", fmt.Sprintf("%d", len(uris))))
	for i, uri := range uris {
		label := "Primary"
		if i > 0 {
			label = fmt.Sprintf("Additional %d", i)
		}
		lines = append(lines, "  "+labeledDetail(label, uri))
	}
	return strings.Join(lines, "\n")
}

func titleStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#5B21B6", Dark: "#C084FC"})
}
func faintStyle() lipgloss.Style  { return lipgloss.NewStyle().Faint(true) }
func statusStyle() lipgloss.Style { return lipgloss.NewStyle().Foreground(lipgloss.Color("214")) }

type referenceClipboard struct {
	nativeWrite func(string) error
	terminal    io.Writer
	isTerminal  func(io.Writer) bool
}

func (c referenceClipboard) Copy(text string) error {
	if c.nativeWrite == nil {
		return errors.New("system clipboard unavailable")
	}
	if err := c.nativeWrite(text); err == nil {
		return nil
	} else if c.terminalAvailable() {
		_, oscErr := osc52.New(text).WriteTo(c.terminal)
		return oscErr
	} else {
		return fmt.Errorf("system clipboard unavailable: %w", err)
	}
}

func (c referenceClipboard) terminalAvailable() bool {
	if c.isTerminal != nil {
		return c.isTerminal(c.terminal)
	}
	return isTerminal(c.terminal)
}

func isTerminal(value any) bool {
	file, ok := value.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(file.Fd()))
}

func openBrowser(target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		(!strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "http")) {
		return fmt.Errorf("refusing to open invalid web URL")
	}

	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target) // #nosec G204 -- target is restricted to an absolute HTTP(S) URL above.
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target) // #nosec G204 -- validated URL argument, fixed executable.
	default:
		command = exec.Command("xdg-open", target) // #nosec G204 -- target is restricted to an absolute HTTP(S) URL above.
	}
	return command.Run()
}

func runResourcesBrowse(cmd *cobra.Command, _ []string) error {
	if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.OutOrStdout()) {
		return errors.New("resources browse requires an interactive terminal")
	}
	store := passbolt.NewConfigStore(viper.GetViper())
	profile, err := store.GetProfile(viper.GetString("profile"))
	if err != nil {
		return err
	}
	storeSecrets := passbolt.NewOSKeyringStore()
	service := passbolt.NewResourceService(storeSecrets)
	auth, err := authServiceFromCommand(cmd, storeSecrets)
	if err != nil {
		return err
	}
	service.Auth = auth
	opts := passboltClientOptions()
	folders, err := service.ListFolders(cmd.Context(), profile, opts...)
	if err != nil {
		return err
	}
	model := newResourceBrowserModel(
		cmd.Context(),
		folders,
		profile.ServerURL,
		func(ctx context.Context, id string) ([]passbolt.ResourceSummary, error) {
			return service.ListFolder(ctx, profile, id, folders, opts...)
		},
		func(ctx context.Context, query string) ([]passbolt.ResourceSummary, error) {
			return service.SearchAll(ctx, profile, query, folders, opts...)
		},
		func(ctx context.Context, id string) (passbolt.DecryptedResource, error) {
			return service.Get(ctx, profile, id, opts...)
		},
		referenceClipboard{nativeWrite: clipboard.WriteAll, terminal: cmd.ErrOrStderr()}.Copy,
		openBrowser,
	)
	_, err = tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithContext(cmd.Context()),
		tea.WithInput(cmd.InOrStdin()),
		tea.WithOutput(cmd.OutOrStdout()),
	).Run()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
