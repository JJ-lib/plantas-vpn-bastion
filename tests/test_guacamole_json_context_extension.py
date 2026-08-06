import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

class JSONContextExtensionTest(unittest.TestCase):
    def test_provider_reauthenticates_user_and_rebuilds_context(self):
        source=(ROOT/'guacamole-json-context-fix/JSONAuthenticationProvider.java').read_text()
        self.assertIn('updateAuthenticatedUser',source)
        self.assertIn('return authenticateUser(credentials);',source)
        self.assertIn('updateUserContext',source)
        self.assertIn('return getUserContext(authenticatedUser);',source)

    def test_build_is_pinned_to_guacamole_160_source_hash(self):
        dockerfile=(ROOT/'guacamole-json-context-fix/Dockerfile').read_text()
        self.assertIn('refs/tags/1.6.0.tar.gz',dockerfile)
        self.assertIn('de5c489471544f93dfc0cc821cf95805aaf9b84e2e3314b6d52e41aeeffd7c16',dockerfile)
        self.assertIn('FROM guacamole/guacamole:1.6.0@sha256:f344085e618bb05e22b964b0208dbd06d3468275bac70206f93805245e067b40',dockerfile)
        self.assertIn('maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237',dockerfile)
        self.assertIn('json-context-1.0.0',dockerfile)
        self.assertIn('jar uf /opt/guacamole/webapp/guacamole.war index.html',dockerfile)

if __name__=='__main__':unittest.main()
