package passbolt

import "sync"

type memorySecretStore struct {
	mu      sync.Mutex
	secrets map[string]string
}

func newMemorySecretStore() *memorySecretStore {
	return &memorySecretStore{secrets: map[string]string{}}
}

func (s *memorySecretStore) Set(profile, name, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[secretUser(profile, name)] = value
	return nil
}

func (s *memorySecretStore) Get(profile, name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.secrets[secretUser(profile, name)]
	if !ok {
		return "", ErrSecretNotFound
	}
	return value, nil
}

func (s *memorySecretStore) Delete(profile, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, secretUser(profile, name))
	return nil
}

func (s *memorySecretStore) DeleteProfile(profile string) error {
	for _, name := range ProfileSecretNames() {
		_ = s.Delete(profile, name)
	}
	return nil
}
