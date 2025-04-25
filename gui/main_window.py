import sys
import threading
import qdarkstyle
from pathlib import Path
from PyQt5 import QtWidgets, QtCore, QtGui, QtWebEngineWidgets
from data_sources import ip_api, subdomains, gdelt, wikidata, urlscan
from analysis.data_aggregator import save_csv


class BaseTab(QtWidgets.QWidget):
    """Uniform button styling and dynamic loading overlay."""
    def __init__(self, parent=None):
        super().__init__(parent)

    def style_button(self, btn: QtWidgets.QPushButton):
        btn.setFont(QtGui.QFont("Segoe UI", 12, QtGui.QFont.Bold))
        btn.setMinimumSize(140, 36)
        btn.setCursor(QtCore.Qt.PointingHandCursor)
        btn.setStyleSheet("""
          QPushButton {
            background-color: #2E7D32; color: white; border-radius: 10px;
          }
          QPushButton:hover {
            background-color: #388E3C;
          }
        """)

    def show_overlay(self, text: str = "Please wait..."):
        self.overlay = QtWidgets.QProgressDialog(text, None, 0, 0, self)
        self.overlay.setWindowModality(QtCore.Qt.WindowModal)
        self.overlay.setCancelButton(None)
        self.overlay.setMinimumDuration(0)
        self.overlay.show()

    def hide_overlay(self):
        if hasattr(self, "overlay") and self.overlay:
            self.overlay.hide()


class GeolocationTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = None
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)
        self.layout().setContentsMargins(10, 10, 10, 10)

        inp = QtWidgets.QGroupBox("IP / Hostname Lookup")
        il = QtWidgets.QHBoxLayout(inp)
        self.ip_input = QtWidgets.QLineEdit()
        self.ip_input.setPlaceholderText("e.g. 8.8.8.8")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.ip_input)
        il.addWidget(self.search_btn)

        res = QtWidgets.QGroupBox("Geolocation Data")
        rl = QtWidgets.QVBoxLayout(res)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(2)
        header_font = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.tree.header().setFont(header_font)
        self.tree.setHeaderLabels(["Key", "Value"])
        self.tree.header().setStretchLastSection(True)
        rl.addWidget(self.tree)

        self.map_view = QtWebEngineWidgets.QWebEngineView()
        self.map_view.settings().setAttribute(
            QtWebEngineWidgets.QWebEngineSettings.LocalContentCanAccessRemoteUrls,
            True
        )
        self.map_view.setMinimumHeight(300)
        self.map_view.hide()

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(res)
        splitter.addWidget(self.map_view)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        self.layout().addWidget(inp)
        self.layout().addWidget(splitter)

    def _on_search(self):
        ip = self.ip_input.text().strip()
        if not ip:
            return
        self.tree.clear()
        self.map_view.hide()
        self.show_overlay("Looking up IP...")
        threading.Thread(target=self._lookup, args=(ip,), daemon=True).start()

    def _lookup(self, ip: str):
        try:
            result = ip_api.lookup(ip)
            QtCore.QMetaObject.invokeMethod(
                self, "_on_result", QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(dict, result)
            )
        except Exception as e:
            QtCore.QMetaObject.invokeMethod(
                self, "_on_error", QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"IP lookup error: {e}")
            )

    @QtCore.pyqtSlot(dict)
    def _on_result(self, res: dict):
        self.hide_overlay()
        self.data = res
        for k, v in res.items():
            item = QtWidgets.QTreeWidgetItem([str(k), str(v)])
            self.tree.addTopLevelItem(item)

        lat, lon = res.get("lat"), res.get("lon")
        if lat is not None and lon is not None:
            html = f"""
            <!DOCTYPE html>
            <html><head>
              <meta charset=\"utf-8\"><title>Map</title>
              <link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet/dist/leaflet.css\"/>
              <script src=\"https://unpkg.com/leaflet/dist/leaflet.js\"></script>
              <style>html,body,#map{{height:100%;margin:0}}</style>
            </head><body>
              <div id=\"map\"></div>
              <script>
                var map = L.map('map').setView([{lat},{lon}],13);
                L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{maxZoom:19}}).addTo(map);
                L.marker([{lat},{lon}]).addTo(map).bindPopup('IP Location').openPopup();
              </script>
            </body></html>
            """
            self.map_view.setHtml(html)
            self.map_view.show()

    @QtCore.pyqtSlot(str)
    def _on_error(self, message: str):
        self.hide_overlay()
        QtWidgets.QMessageBox.warning(self, "Error", message)


class DomainLookupTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = None
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)
        self.layout().setContentsMargins(10, 10, 10, 10)

        inp = QtWidgets.QGroupBox("DNS Host Records")
        il = QtWidgets.QHBoxLayout(inp)
        self.domain_input = QtWidgets.QLineEdit()
        self.domain_input.setPlaceholderText("e.g. example.com")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.domain_input)
        il.addWidget(self.search_btn)

        res = QtWidgets.QGroupBox("Subdomains")
        rl = QtWidgets.QVBoxLayout(res)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(1)
        header_font = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.tree.header().setFont(header_font)
        self.tree.setHeaderLabels(["Subdomain"])
        rl.addWidget(self.tree)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(inp)
        splitter.addWidget(res)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        self.layout().addWidget(splitter)

    def _on_search(self):
        dom = self.domain_input.text().strip()
        if not dom:
            return
        self.tree.clear()
        self.show_overlay("Looking up subdomains...")
        threading.Thread(target=self._lookup, args=(dom,), daemon=True).start()

    def _lookup(self, dom: str):
        try:
            subs = subdomains.get_subdomains(dom)
            QtCore.QMetaObject.invokeMethod(
                self, "_on_result", QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(list, subs)
            )
        except Exception as e:
            QtCore.QMetaObject.invokeMethod(
                self, "_on_error", QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"Subdomain lookup error: {e}")
            )

    @QtCore.pyqtSlot(list)
    def _on_result(self, subs: list):
        self.hide_overlay()
        # Handle no results or invalid input
        if not subs:
            QtWidgets.QMessageBox.information(
                self,
                "No Results",
                f"No subdomains found for '{self.domain_input.text()}'"
            )
            return
        self.data = subs
        for s in subs:
            QtWidgets.QTreeWidgetItem(self.tree, [s])

    @QtCore.pyqtSlot(str)
    def _on_error(self, message: str):
        self.hide_overlay()
        QtWidgets.QMessageBox.warning(self, "Error", message)


class KeywordSearchTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = {}
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)
        self.layout().setContentsMargins(10, 10, 10, 10)

        inp = QtWidgets.QGroupBox("Keyword Search")
        il = QtWidgets.QHBoxLayout(inp)
        self.keyword_input = QtWidgets.QLineEdit()
        self.keyword_input.setPlaceholderText("Enter a keyword")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.keyword_input)
        il.addWidget(self.search_btn)

        res = QtWidgets.QGroupBox("Results")
        rl = QtWidgets.QVBoxLayout(res)
        self.tree = QtWidgets.QTreeWidget()
        header_font = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.tree.header().setFont(header_font)
        self.tree.setHeaderLabels(["Source", "Title/Label", "Info"] )
        rl.addWidget(self.tree)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(inp)
        splitter.addWidget(res)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        self.layout().addWidget(splitter)

    def _on_search(self):
        kw = self.keyword_input.text().strip()
        if not kw:
            return
        self.tree.clear()
        self.show_overlay("Searching keywords...")
        threading.Thread(target=self._lookup, args=(kw,), daemon=True).start()

    def _lookup(self, kw: str):
        # articles
        articles = gdelt.search_articles(kw)
        if not articles:
            QtCore.QMetaObject.invokeMethod(
                self, "_on_error", QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"No GDELT articles for '{kw}'")
            )
            return
        # entities
        try:
            entities = wikidata.entity_search(kw)
        except Exception as e:
            QtCore.QMetaObject.invokeMethod(
                self, "_on_error", QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"Wikidata error: {e}")
            )
            return
        QtCore.QMetaObject.invokeMethod(
            self, "_on_result", QtCore.Qt.QueuedConnection,
            QtCore.Q_ARG(list, articles), QtCore.Q_ARG(list, entities)
        )

    @QtCore.pyqtSlot(list, list)
    def _on_result(self, articles: list, entities: list):
        self.hide_overlay()
        self.data = {"gdelt": articles, "wikidata": entities}
        root1 = QtWidgets.QTreeWidgetItem(self.tree, ["GDELT"])
        for a in articles:
            title = a.get("title", "<no-title>")
            src = a.get("domain", a.get("source", ""))
            QtWidgets.QTreeWidgetItem(root1, ["", title, src])
        root2 = QtWidgets.QTreeWidgetItem(self.tree, ["Wikidata"])
        for e in entities:
            lbl = e.get("label", "")
            desc = e.get("description", "")
            QtWidgets.QTreeWidgetItem(root2, ["", lbl, desc])
        self.tree.expandAll()

    @QtCore.pyqtSlot(str)
    def _on_error(self, message: str):
        self.hide_overlay()
        QtWidgets.QMessageBox.warning(self, "Search Error", message)


class URLScanTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = None
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)
        self.layout().setContentsMargins(10, 10, 10, 10)

        inp = QtWidgets.QGroupBox("URL Scan")
        il = QtWidgets.QHBoxLayout(inp)
        self.url_input = QtWidgets.QLineEdit()
        self.url_input.setPlaceholderText("e.g. example.com")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.url_input)
        il.addWidget(self.search_btn)

        res = QtWidgets.QGroupBox("Scan Results")
        rl = QtWidgets.QVBoxLayout(res)
        headers = ["Domain", "IP", "PTR", "ASN", "ASN Name", "URL"]
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(len(headers))
        hf = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.tree.header().setFont(hf)
        self.tree.setHeaderLabels(headers)
        rl.addWidget(self.tree)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(inp)
        splitter.addWidget(res)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        self.layout().addWidget(splitter)

    def _on_search(self):
        url = self.url_input.text().strip()
        if not url:
            return
        self.tree.clear()
        self.show_overlay("Scanning URL...")
        threading.Thread(target=self._lookup, args=(url,), daemon=True).start()

    def _lookup(self, url: str):
        try:
            scans = urlscan.search(url)
        except Exception as e:
            QtCore.QMetaObject.invokeMethod(
                self, "_on_error", QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"URLScan error: {e}")
            )
            return
        target = url.lower().split("//")[-1].split("/")[0]
        filtered = [s for s in scans if target in s.get("page", {}).get("url", "")]
        QtCore.QMetaObject.invokeMethod(
            self, "_on_result", QtCore.Qt.QueuedConnection,
            QtCore.Q_ARG(list, filtered)
        )

    @QtCore.pyqtSlot(list)
    def _on_result(self, scans: list):
        self.hide_overlay()
        # Handle no scan results or invalid input
        if not scans:
            QtWidgets.QMessageBox.information(
                self,
                "No Results",
                f"No scan results found for '{self.url_input.text()}'"
            )
            return
        self.data = scans
        for s in scans:
            p = s.get("page", {})
            QtWidgets.QTreeWidgetItem(self.tree, [
                p.get("domain", ""), p.get("ip", ""),
                p.get("ptr", ""), p.get("asn", ""),
                p.get("asnname", ""), p.get("url", "")
            ])

    @QtCore.pyqtSlot(str)
    def _on_error(self, message: str):
        self.hide_overlay()
        QtWidgets.QMessageBox.warning(self, "Scan Error", message)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Dashboard")
        self.resize(1200, 800)

        QtWidgets.QApplication.instance().setStyleSheet(
            qdarkstyle.load_stylesheet_pyqt5()
        )
        QtWidgets.QApplication.instance().setFont(QtGui.QFont("Segoe UI", 10))

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(GeolocationTab(), "Geolocation")
        self.tabs.addTab(DomainLookupTab(), "Domain Lookup")
        self.tabs.addTab(KeywordSearchTab(), "Keyword Search")
        self.tabs.addTab(URLScanTab(), "URL Scan")

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.addWidget(self.tabs)

        export_btn = QtWidgets.QPushButton("Export CSV")
        BaseTab.style_button(self, export_btn)
        export_btn.setIcon(QtGui.QIcon.fromTheme("document-save"))
        export_btn.clicked.connect(self.export_all)
        self.statusBar().addPermanentWidget(export_btn)

        self.setCentralWidget(central)

    def export_all(self):
        # Gather data from tabs
        raw_ip = getattr(self.tabs.widget(0), 'data', None)
        raw_domain = getattr(self.tabs.widget(1), 'data', None)
        raw_keyword = getattr(self.tabs.widget(2), 'data', None)
        raw_urlscan = getattr(self.tabs.widget(3), 'data', None)

        payload = {}
        if raw_ip:
            payload['ip'] = raw_ip
        if raw_domain:
            payload['domain'] = {'subdomains': raw_domain}
        if raw_keyword:
            payload['keyword'] = raw_keyword
        if raw_urlscan:
            payload['urlscan'] = raw_urlscan

        if not payload:
            QtWidgets.QMessageBox.warning(self, "Nothing to export",
                                          "Run at least one lookup first")
            return

        folder = save_csv(payload)
        QtWidgets.QMessageBox.information(
            self,
            "Exported",
            f"CSVs saved to:\n{Path(folder).resolve()}"
        )


def run_app():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    run_app()
