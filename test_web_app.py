"""Web API tests. Install requirements.txt to run these tests."""
import io
import unittest

try:
    import flask  # noqa: F401
except ImportError:
    flask = None


@unittest.skipIf(flask is None, "Flask is not installed; run: python -m pip install -r requirements.txt")
class TestWebApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as web_app
        cls.web_app = web_app
        web_app.app.config.update(TESTING=True, MAX_CONTENT_LENGTH=5 * 1024 * 1024)

    def setUp(self):
        self.client = self.web_app.app.test_client()

    def test_dashboard(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SSH Log Analyzer', response.data)

    def test_health(self):
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['status'], 'ok')

    def test_sample_analysis(self):
        response = self.client.get('/api/sample')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['sample_data'])
        self.assertIn('total_events', data['summary'])
        self.assertIn('events_over_time', data['summary'])
        self.assertIn('json', data['reports'])

    def test_upload_valid_log_and_report_download(self):
        content = (b'Oct 27 03:14:22 host sshd[1]: Failed password for ubuntu from 203.0.113.5 port 4444 ssh2\n'
                   b'Oct 27 03:14:23 host sshd[1]: Failed password for ubuntu from 203.0.113.5 port 4444 ssh2\n')
        response = self.client.post('/api/analyze', data={'year': '2026', 'file': (io.BytesIO(content), 'auth.log')}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertFalse(data['sample_data'])
        self.assertEqual(data['summary']['failed_logins'], 2)
        report = self.client.get(data['reports']['json'])
        self.assertEqual(report.status_code, 200)
        report.close()

    def test_reject_unsupported_file(self):
        response = self.client.post('/api/analyze', data={'file': (io.BytesIO(b'hello'), 'log.exe')}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 415)

    def test_reject_empty_file(self):
        response = self.client.post('/api/analyze', data={'file': (io.BytesIO(b''), 'empty.log')}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_invalid_report_id(self):
        response = self.client.get('/api/reports/not-a-real-id/json')
        self.assertEqual(response.status_code, 404)

    def test_sample_rejects_bad_year(self):
        self.assertEqual(self.client.get('/api/sample?year=abc').status_code, 400)
        self.assertEqual(self.client.get('/api/sample?year=99999').status_code, 400)

    def test_upload_rejects_bad_year(self):
        response = self.client.post('/api/analyze', data={'year': 'abc', 'file': (io.BytesIO(b'x\n'), 'a.log')}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_security_headers(self):
        response = self.client.get('/')
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])

    def test_html_report_escapes_hostile_username(self):
        lines = ''.join('Oct 27 03:00:%02d h sshd[1]: Failed password for invalid user <script>alert(1)</script> from 6.6.6.6 port 22 ssh2\n' % i for i in range(12))
        response = self.client.post('/api/analyze', data={'year': '2026', 'file': (io.BytesIO(lines.encode()), 'evil.log')}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        page = self.client.get(response.get_json()['reports']['html'])
        self.assertNotIn(b'<script>alert(1)', page.data)
        self.assertIn(b'&lt;script&gt;', page.data)
        self.assertIn("default-src 'none'", page.headers['Content-Security-Policy'])
        page.close()

    def test_expired_reports_are_deleted(self):
        data = self.client.get('/api/sample').get_json()
        rid = data['report_id']
        report_dir = self.web_app._REPORTS[rid]['dir']
        self.assertTrue(report_dir.exists())
        self.web_app._cleanup_reports(now=__import__('time').time() + self.web_app.REPORT_TTL_SECONDS + 5)
        self.assertNotIn(rid, self.web_app._REPORTS)
        self.assertFalse(report_dir.exists())
        self.assertEqual(self.client.get(data['reports']['json']).status_code, 404)

    def test_report_count_is_capped(self):
        original = self.web_app.MAX_REPORTS
        self.web_app.MAX_REPORTS = 3
        try:
            for _ in range(6):
                self.client.get('/api/sample')
            self.web_app._cleanup_reports()
            self.assertLessEqual(len(self.web_app._REPORTS), 3)
        finally:
            self.web_app.MAX_REPORTS = original


if __name__ == '__main__':
    unittest.main()
