CREATE TABLE schema_migrations(
  version INTEGER PRIMARY KEY,
  applied_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE identity(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  device_id BLOB NOT NULL CHECK(length(device_id) = 32),
  public_key BLOB NOT NULL CHECK(length(public_key) = 32),
  secret_handle TEXT NOT NULL,
  created_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE relay_enrollments(
  relay_url TEXT PRIMARY KEY,
  relay_pin BLOB,
  tenant TEXT NOT NULL DEFAULT '',
  enrollment_generation INTEGER NOT NULL,
  auto_connect INTEGER NOT NULL DEFAULT 1 CHECK(auto_connect IN (0, 1)),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
  updated_unix_milliseconds INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE password_verifier(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  format_version INTEGER NOT NULL,
  encoded TEXT NOT NULL,
  operations INTEGER NOT NULL,
  memory_bytes INTEGER NOT NULL,
  password_generation INTEGER NOT NULL
);
CREATE TABLE trust_grants(
  grant_id BLOB PRIMARY KEY CHECK(length(grant_id) = 16),
  direction INTEGER NOT NULL CHECK(direction IN (1, 2)),
  issuer_device_id BLOB NOT NULL CHECK(length(issuer_device_id) = 32),
  subject_device_id BLOB NOT NULL CHECK(length(subject_device_id) = 32),
  password_generation INTEGER NOT NULL,
  issued_unix_milliseconds INTEGER NOT NULL,
  expires_unix_milliseconds INTEGER,
  signature BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
  revoked_unix_milliseconds INTEGER
);
CREATE TABLE trust_grant_scopes(
  grant_id BLOB NOT NULL REFERENCES trust_grants(grant_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  PRIMARY KEY(grant_id, scope)
);
CREATE INDEX trust_grants_subject_index
  ON trust_grants(subject_device_id, direction, revoked, expires_unix_milliseconds);
CREATE TABLE endpoint_records(
  application_id TEXT PRIMARY KEY,
  endpoint_id BLOB NOT NULL UNIQUE CHECK(length(endpoint_id) = 16),
  created_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE file_resume(
  transfer_id BLOB PRIMARY KEY CHECK(length(transfer_id) = 16),
  peer_device_id BLOB NOT NULL CHECK(length(peer_device_id) = 32),
  state BLOB NOT NULL,
  updated_unix_milliseconds INTEGER NOT NULL
);
CREATE TABLE preferences(
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  updated_unix_milliseconds INTEGER NOT NULL
);
INSERT INTO schema_migrations(version, applied_unix_milliseconds) VALUES(1, 1);
PRAGMA application_id=1213808976;
PRAGMA user_version=1;
