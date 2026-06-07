package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	injectcore "github.com/emqmalte/bolty/internal/inject"
	"github.com/emqmalte/bolty/internal/passbolt"
)

const testResourceID = "ae60d89c-f13b-4fb1-b2dc-c8dc806cac88"
const testFolderID = "f1b79505-2371-422f-88d8-9c6326806b3d"

func newTestBrowser(t *testing.T) resourceBrowserModel {
	t.Helper()
	return newResourceBrowserModel(
		context.Background(),
		[]passbolt.FolderSummary{{ID: testFolderID, Name: "Engineering"}},
		"https://passbolt.test",
		func(_ context.Context, folderID string) ([]passbolt.ResourceSummary, error) {
			if folderID == "" {
				return []passbolt.ResourceSummary{{
					ID: testResourceID, Name: "Root API", Username: "ada", URI: "https://api.test",
				}}, nil
			}
			return []passbolt.ResourceSummary{{
				ID: testResourceID, Name: "Folder API", FolderParentID: testFolderID, FolderPath: "Engineering",
			}}, nil
		},
		func(_ context.Context, query string) ([]passbolt.ResourceSummary, error) {
			return []passbolt.ResourceSummary{{ID: testResourceID, Name: "Global " + query}}, nil
		},
		func(_ context.Context, id string) (passbolt.DecryptedResource, error) {
			return passbolt.DecryptedResource{
				ID: id, DecryptedName: "Root API",
				Metadata: map[string]any{
					"username": "ada",
					"uris":     []any{"https://api.test", "https://admin.api.test"},
				},
				Secrets: []any{map[string]any{
					"password":    "must-not-render",
					"description": strings.Repeat("A long resource description. ", 12),
					"totp": map[string]any{
						"secret_key": "DAV3DS4ERAAF5QGH",
						"period":     float64(30),
						"digits":     float64(6),
						"algorithm":  "SHA1",
					},
				}},
			}, nil
		},
		func(string) error { return nil },
		func(string) error { return nil },
	)
}

func initializeBrowser(t *testing.T, model resourceBrowserModel) resourceBrowserModel {
	t.Helper()
	cmd := model.Init()
	updated, _ := model.Update(cmd())
	return updated.(resourceBrowserModel)
}

func TestResourceBrowserLoadsOnlyRootInitially(t *testing.T) {
	t.Parallel()

	var loaded []string
	model := newResourceBrowserModel(
		context.Background(),
		[]passbolt.FolderSummary{{ID: testFolderID, Name: "Engineering"}},
		"https://passbolt.test",
		func(_ context.Context, folderID string) ([]passbolt.ResourceSummary, error) {
			loaded = append(loaded, folderID)
			return nil, nil
		},
		nil, nil, nil, nil,
	)
	model = initializeBrowser(t, model)
	if len(loaded) != 1 || loaded[0] != "" {
		t.Fatalf("initial loads = %v, want root only", loaded)
	}
	if len(model.folderRows) != 2 || model.folderRows[0].Label != "Root" || !strings.Contains(model.folderRows[1].Label, "Engineering") {
		t.Fatalf("expected root and child folder tree, got %#v", model.folderRows)
	}
}

func TestResourceBrowserStartsInLoadingState(t *testing.T) {
	t.Parallel()

	model := newTestBrowser(t)
	if !model.loading {
		t.Fatal("browser should block input until the initial directory is loaded")
	}
}

func TestFolderTreeRowsRenderHierarchy(t *testing.T) {
	t.Parallel()

	rows := buildFolderTreeRows([]passbolt.FolderSummary{
		{ID: "production", ParentID: "engineering", Name: "Production"},
		{ID: "engineering", Name: "Engineering"},
		{ID: "finance", Name: "Finance"},
	})
	if len(rows) != 4 || rows[0].Label != "Root" {
		t.Fatalf("unexpected tree rows: %#v", rows)
	}
	var production string
	for _, row := range rows {
		if row.ID == "production" {
			production = row.Label
		}
	}
	if !strings.HasPrefix(production, "  ") || !strings.Contains(production, "Production") {
		t.Fatalf("nested folder was not indented: %q", production)
	}
}

func TestResourceBrowserSwitchesBetweenPanes(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	if model.pane != folderPane || !model.folderTree.Focused() || model.resources.Focused() {
		t.Fatal("folder tree should be focused initially")
	}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	model = updated.(resourceBrowserModel)
	if model.pane != resourcePane || model.folderTree.Focused() || !model.resources.Focused() {
		t.Fatal("tab should focus the resource pane")
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyLeft})
	model = updated.(resourceBrowserModel)
	if model.pane != folderPane {
		t.Fatal("left should focus the folder pane")
	}
}

func TestResourceBrowserNavigatesFoldersAndUsesCache(t *testing.T) {
	t.Parallel()

	calls := map[string]int{}
	model := newResourceBrowserModel(
		context.Background(),
		[]passbolt.FolderSummary{{ID: testFolderID, Name: "Engineering"}},
		"https://passbolt.test",
		func(_ context.Context, folderID string) ([]passbolt.ResourceSummary, error) {
			calls[folderID]++
			return []passbolt.ResourceSummary{{ID: testResourceID, Name: "API"}}, nil
		},
		nil, nil, nil, nil,
	)
	model = initializeBrowser(t, model)

	model.folderTree.SetCursor(1)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)
	if model.currentDir != testFolderID || calls[testFolderID] != 1 {
		t.Fatalf("folder was not loaded: dir=%q calls=%v", model.currentDir, calls)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'u'}})
	model = updated.(resourceBrowserModel)
	model.folderTree.SetCursor(1)
	updated, cmd = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	if cmd != nil || calls[testFolderID] != 1 {
		t.Fatalf("cached folder should not reload: calls=%v", calls)
	}
}

func TestResourceBrowserLocalFilterUsesLoadedEntries(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	model.pane = resourcePane
	model.syncPaneFocus()
	model.search.SetValue("root api")
	model.applyLocalFilter()
	if len(model.filtered) != 1 || model.filtered[0].resource.Name != "Root API" {
		t.Fatalf("unexpected local filter: %#v", model.filtered)
	}
}

func TestResourceBrowserGlobalSearchIsExplicit(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	model = updated.(resourceBrowserModel)
	if !model.search.Focused() || model.mode != globalSearchMode {
		t.Fatal("g should start global search mode")
	}
	model.search.SetValue("database")
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	if cmd == nil || !model.loading {
		t.Fatal("global search should run an async command")
	}
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)
	if len(model.filtered) != 1 || model.filtered[0].resource.Name != "Global database" {
		t.Fatalf("unexpected global results: %#v", model.filtered)
	}
}

func TestResourceBrowserDetailMasksAndRevealsSensitiveValues(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	model.pane = resourcePane
	model.syncPaneFocus()
	model.resources.SetCursor(0)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)
	if !strings.Contains(model.View(), "https://api.test") || !strings.Contains(model.View(), "https://admin.api.test") {
		t.Fatal("detail should display primary and additional URIs")
	}
	fields := injectSelectors(model.resource)
	if strings.Contains(","+strings.Join(fields, ",")+",", ",url,") {
		t.Fatal("detail should not present url as a duplicate injectable field")
	}
	if strings.Contains(model.View(), "must-not-render") {
		t.Fatal("password should be masked by default")
	}
	if !strings.Contains(","+strings.Join(fields, ",")+",", ",totp,") {
		t.Fatal("detail should list a Passbolt TOTP object as injectable")
	}
	if strings.Contains(model.View(), "DAV3DS4ERAAF5QGH") {
		t.Fatal("TOTP secret should never be rendered")
	}
	selected := len(fields) - 1
	model.fields.SetCursor(selected)
	selectedField := model.fields.SelectedRow()
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	model = updated.(resourceBrowserModel)
	if !strings.Contains(model.View(), "must-not-render") {
		t.Fatal("r should reveal field values")
	}
	if model.fields.Cursor() != selected {
		t.Fatalf("reveal moved cursor from %d to %d", selected, model.fields.Cursor())
	}
	if row := model.fields.SelectedRow(); len(row) == 0 || len(selectedField) == 0 || row[0] != selectedField[0] {
		t.Fatalf("reveal changed selection from %#v to %#v", selectedField, row)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	model = updated.(resourceBrowserModel)
	if model.fields.Cursor() != selected {
		t.Fatalf("hide moved cursor from %d to %d", selected, model.fields.Cursor())
	}
}

func TestResourceBrowserCopiesSelectedFieldValueWithoutRenderingIt(t *testing.T) {
	t.Parallel()

	var copied string
	model := initializeBrowser(t, newTestBrowser(t))
	model.copy = func(value string) error {
		copied = value
		return nil
	}
	model.pane = resourcePane
	model.syncPaneFocus()
	model.resources.SetCursor(0)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)

	passwordIndex := -1
	for i, selector := range injectSelectors(model.resource) {
		if selector == "password" {
			passwordIndex = i
			break
		}
	}
	if passwordIndex < 0 {
		t.Fatal("password field not found")
	}
	model.fields.SetCursor(passwordIndex)
	updated, cmd = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)

	if copied != "must-not-render" {
		t.Fatalf("copied value = %q", copied)
	}
	if strings.Contains(model.status, copied) {
		t.Fatal("copy status must not reveal the copied secret")
	}
	if !strings.Contains(model.status, "Copied value of Password") {
		t.Fatalf("unexpected status: %q", model.status)
	}
}

func TestResourceBrowserCopiesCurrentTOTPCode(t *testing.T) {
	t.Parallel()

	var copied string
	model := initializeBrowser(t, newTestBrowser(t))
	model.copy = func(value string) error {
		copied = value
		return nil
	}
	model.pane = resourcePane
	model.syncPaneFocus()
	model.resources.SetCursor(0)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)

	for i, selector := range injectSelectors(model.resource) {
		if selector == "totp" {
			model.fields.SetCursor(i)
			break
		}
	}
	updated, cmd = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)

	if !regexp.MustCompile(`^\d{6}$`).MatchString(copied) {
		t.Fatalf("copied TOTP value = %q", copied)
	}
	if !strings.Contains(model.status, "Copied value of TOTP") {
		t.Fatalf("unexpected status: %q", model.status)
	}
}

func TestResourceBrowserTOTPTickPreservesFieldSelection(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	model.pane = resourcePane
	model.syncPaneFocus()
	model.resources.SetCursor(0)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)

	fields := injectSelectors(model.resource)
	if len(fields) < 3 {
		t.Fatalf("expected multiple fields, got %v", fields)
	}
	selected := len(fields) - 1
	model.fields.SetCursor(selected)
	before := model.fields.SelectedRow()

	updated, _ = model.Update(totpTickMsg(time.Now()))
	model = updated.(resourceBrowserModel)

	if model.fields.Cursor() != selected {
		t.Fatalf("cursor moved from %d to %d", selected, model.fields.Cursor())
	}
	after := model.fields.SelectedRow()
	if len(before) == 0 || len(after) == 0 || before[0] != after[0] {
		t.Fatalf("selection changed from %#v to %#v", before, after)
	}
}

func TestTOTPExpiryIndicatorUsesConfiguredPeriod(t *testing.T) {
	t.Parallel()

	status := injectcore.TOTPStatus{
		Code:      "123456",
		Period:    45 * time.Second,
		ExpiresAt: time.Unix(100, 0),
	}
	got := totpExpiryIndicator(status, time.Unix(70, 0))
	if !strings.Contains(got, "30s") || !strings.Contains(got, "●") || !strings.Contains(got, "○") {
		t.Fatalf("unexpected expiry indicator: %q", got)
	}
}

func TestTOTPDisplayWidthIsStable(t *testing.T) {
	t.Parallel()

	status := injectcore.TOTPStatus{
		Code:      "123456",
		Digits:    6,
		Period:    30 * time.Second,
		ExpiresAt: time.Unix(100, 0),
	}
	hidden := formatTOTPValue(status, false, time.Unix(90, 0))
	revealed := formatTOTPValue(status, true, time.Unix(90, 0))
	nextSecond := formatTOTPValue(status, true, time.Unix(91, 0))
	if len([]rune(hidden)) != len([]rune(revealed)) {
		t.Fatalf("hidden width %d != revealed width %d: %q / %q", len([]rune(hidden)), len([]rune(revealed)), hidden, revealed)
	}
	if len([]rune(revealed)) != len([]rune(nextSecond)) {
		t.Fatalf("countdown changed width: %q / %q", revealed, nextSecond)
	}
	if !strings.HasPrefix(hidden, "••••••••") || !strings.HasPrefix(revealed, "123456  ") {
		t.Fatalf("unexpected fixed token slots: %q / %q", hidden, revealed)
	}
}

func TestMaskedSecretValueHasStaticLength(t *testing.T) {
	t.Parallel()

	if got := maskedSecretValue(); got != "••••••••" {
		t.Fatalf("maskedSecretValue() = %q", got)
	}
}

func TestResourceBrowserTOTPTickRecalculatesOnlyAtExpiry(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	model.pane = resourcePane
	model.syncPaneFocus()
	model.resources.SetCursor(0)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)

	original := model.totp
	beforeExpiry := original.ExpiresAt.Add(-time.Second)
	updated, _ = model.Update(totpTickMsg(beforeExpiry))
	model = updated.(resourceBrowserModel)
	if model.totp.Code != original.Code || !model.totp.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("TOTP should not be recalculated before expiry")
	}

	updated, _ = model.Update(totpTickMsg(original.ExpiresAt))
	model = updated.(resourceBrowserModel)
	if !model.totp.ExpiresAt.After(original.ExpiresAt) {
		t.Fatalf("TOTP expiry did not advance: before=%v after=%v", original.ExpiresAt, model.totp.ExpiresAt)
	}
}

func TestResourceBrowserOffersScrollableFullDescription(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	model.width = 60
	model.height = 12
	model.resize()
	model.pane = resourcePane
	model.syncPaneFocus()
	model.resources.SetCursor(0)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resourceBrowserModel)
	updated, _ = model.Update(cmd())
	model = updated.(resourceBrowserModel)

	if !strings.Contains(model.View(), "[truncated; press d]") {
		t.Fatal("detail should mark a truncated description")
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	model = updated.(resourceBrowserModel)
	if model.view != descriptionBrowserView {
		t.Fatal("d should open the full description")
	}
	if !strings.Contains(model.View(), "A long resource description.") {
		t.Fatal("full description view should contain description text")
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(resourceBrowserModel)
	if model.view != fieldBrowserView {
		t.Fatal("escape should return to resource details")
	}
}

func TestResourceBrowserBuildsPassboltWebURLs(t *testing.T) {
	t.Parallel()

	model := initializeBrowser(t, newTestBrowser(t))
	target, ok := model.selectedWebURL()
	if ok || target != "" {
		t.Fatalf("root folder should not have a web URL: %q", target)
	}
	model.folderTree.SetCursor(1)
	target, ok = model.selectedWebURL()
	if !ok || target != "https://passbolt.test/app/folders/view/"+testFolderID {
		t.Fatalf("folder URL = %q", target)
	}
	model.view = fieldBrowserView
	model.resource.ID = testResourceID
	target, ok = model.selectedWebURL()
	if !ok || target != "https://passbolt.test/app/passwords/view/"+testResourceID {
		t.Fatalf("resource URL = %q", target)
	}
}

func TestOpenBrowserRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"file:///tmp/secret",
		"javascript:alert(1)",
		"https://user:password@passbolt.test/app",
		"https:///missing-host",
	} {
		if err := openBrowser(target); err == nil {
			t.Fatalf("openBrowser(%q) unexpectedly succeeded", target)
		}
	}
}

func TestResourceTableColumnsRespondToWidthAndOmitUUID(t *testing.T) {
	t.Parallel()

	narrow := resourceTableColumns(45)
	wide := resourceTableColumns(120)
	if len(narrow) != 1 || len(wide) != 4 {
		t.Fatalf("unexpected responsive columns: narrow=%v wide=%v", narrow, wide)
	}
	for _, columns := range [][]table.Column{narrow, wide} {
		for _, column := range columns {
			if column.Title == "ID" || column.Title == "UUID" {
				t.Fatal("UUID should not be displayed as a table column")
			}
		}
	}
	rows := resourceTableRows([]browserEntry{{
		resource: passbolt.ResourceSummary{Name: "API"},
	}}, narrow)
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] != "API" {
		t.Fatalf("narrow row should retain the resource name: %#v", rows)
	}
}

func TestResourceTableRowsDisplayPrimaryURI(t *testing.T) {
	t.Parallel()

	columns := resourceTableColumns(120)
	rows := resourceTableRows([]browserEntry{{
		resource: passbolt.ResourceSummary{
			Name: "API",
			URI:  "https://primary.test",
			URIs: []string{"https://primary.test", "https://secondary.test"},
		},
	}}, columns)
	if len(rows) != 1 || len(rows[0]) != 4 || rows[0][3] != "https://primary.test" {
		t.Fatalf("unexpected resource row: %#v", rows)
	}
}

func injectSelectors(resource passbolt.DecryptedResource) []string {
	fields := injectcore.AvailableFields(resource)
	selectors := make([]string, len(fields))
	for i, field := range fields {
		selectors[i] = field.Selector
	}
	return selectors
}

func TestSafeDisplayTextRemovesTerminalControls(t *testing.T) {
	t.Parallel()
	got := safeDisplayText("api\n\x1b[31mproduction")
	if strings.ContainsAny(got, "\n\x1b") {
		t.Fatalf("control characters were not removed: %q", got)
	}
}

func TestReferenceClipboardUsesNativeClipboardFirst(t *testing.T) {
	t.Parallel()
	var got string
	var terminal bytes.Buffer
	copier := referenceClipboard{
		nativeWrite: func(value string) error { got = value; return nil },
		terminal:    &terminal,
		isTerminal:  func(io.Writer) bool { return true },
	}
	if err := copier.Copy("reference"); err != nil {
		t.Fatal(err)
	}
	if got != "reference" || terminal.Len() != 0 {
		t.Fatalf("native=%q terminal=%q", got, terminal.String())
	}
}

func TestReferenceClipboardFallsBackToOSC52(t *testing.T) {
	t.Parallel()
	var terminal bytes.Buffer
	copier := referenceClipboard{
		nativeWrite: func(string) error { return errors.New("unavailable") },
		terminal:    &terminal,
		isTerminal:  func(io.Writer) bool { return true },
	}
	if err := copier.Copy("reference"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal.String(), "\x1b]52;c;") {
		t.Fatalf("expected OSC52 sequence, got %q", terminal.String())
	}
}
