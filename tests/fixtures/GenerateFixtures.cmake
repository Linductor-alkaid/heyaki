if(NOT DEFINED HEYAKI_FIXTURE_DIR OR NOT DEFINED HEYAKI_OPENSSL_EXECUTABLE OR
   NOT DEFINED HEYAKI_SQLITE3_EXECUTABLE)
  message(FATAL_ERROR "Fixture directory, OpenSSL, and sqlite3 are required")
endif()

file(MAKE_DIRECTORY "${HEYAKI_FIXTURE_DIR}/credentials")
file(MAKE_DIRECTORY "${HEYAKI_FIXTURE_DIR}/profiles")
file(REMOVE
  "${HEYAKI_FIXTURE_DIR}/credentials/test-only-key.pem"
  "${HEYAKI_FIXTURE_DIR}/credentials/test-only-cert.pem"
  "${HEYAKI_FIXTURE_DIR}/relay.sqlite"
  "${HEYAKI_FIXTURE_DIR}/profiles/default.sqlite")

execute_process(
  COMMAND "${HEYAKI_OPENSSL_EXECUTABLE}" req -x509 -newkey rsa:2048 -nodes
    -keyout "${HEYAKI_FIXTURE_DIR}/credentials/test-only-key.pem"
    -out "${HEYAKI_FIXTURE_DIR}/credentials/test-only-cert.pem"
    -subj "/CN=heyaki.invalid" -days 1 -set_serial 1
  RESULT_VARIABLE openssl_result
  OUTPUT_QUIET
  ERROR_QUIET)
if(NOT openssl_result EQUAL 0)
  message(FATAL_ERROR "OpenSSL failed to generate the test-only certificate")
endif()

execute_process(
  COMMAND "${HEYAKI_SQLITE3_EXECUTABLE}" "${HEYAKI_FIXTURE_DIR}/relay.sqlite"
    "PRAGMA application_id=1213808969; CREATE TABLE fixture_marker(kind TEXT NOT NULL); INSERT INTO fixture_marker VALUES('TEST_ONLY');"
  RESULT_VARIABLE relay_db_result)
execute_process(
  COMMAND "${HEYAKI_SQLITE3_EXECUTABLE}" "${HEYAKI_FIXTURE_DIR}/profiles/default.sqlite"
    "PRAGMA application_id=1213808976; CREATE TABLE fixture_marker(kind TEXT NOT NULL); INSERT INTO fixture_marker VALUES('TEST_ONLY');"
  RESULT_VARIABLE profile_db_result)
if(NOT relay_db_result EQUAL 0 OR NOT profile_db_result EQUAL 0)
  message(FATAL_ERROR "sqlite3 failed to generate test-only database fixtures")
endif()

string(RANDOM LENGTH 40 ALPHABET 0123456789abcdefghijklmnopqrstuvwxyz bootstrap_token)
file(WRITE "${HEYAKI_FIXTURE_DIR}/bootstrap-token.txt"
  "TEST-ONLY-${bootstrap_token}\n")
file(WRITE "${HEYAKI_FIXTURE_DIR}/manifest.txt"
  "HEYAKI TEST FIXTURES ONLY\nNo generated credential is valid outside tests.\n")

