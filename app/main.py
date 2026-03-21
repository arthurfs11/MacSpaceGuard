from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QAction, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QComboBox,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:
    from send2trash import send2trash
except Exception:
    send2trash = None


APP_NAME = "Mac Space Guard"
DEFAULT_SCAN_TARGETS = [
    Path.home() / "Library" / "Application Support",
    Path.home() / "Library" / "Containers",
    Path.home() / "Library" / "Group Containers",
    Path.home() / "Downloads",
    Path.home() / "Pictures",
]
PROTECTED_PATH_HINTS = [
    "/Library/Containers/",
    "/Library/Group Containers/",
]


@dataclass
class ScanResult:
    path: Path
    size_bytes: int
    category: str
    safety: str
    note: str
    action_hint: str


def format_bytes(num: int) -> str:
    value = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} EB"


RULES: dict[str, tuple[str, str, str, str]] = {
    "Google": ("Browser", "Revisar", "Pode conter perfil, cache e sessão do navegador.", "Fechar Chrome/Arc antes de limpar."),
    "Chrome": ("Browser", "Revisar", "Pode conter perfil, cache e sessão do navegador.", "Fechar Chrome antes de limpar."),
    "Code": ("IDE", "Seguro", "Normalmente contém cache e dados do VS Code.", "Pode mover para a Lixeira com segurança na maioria dos casos."),
    "Cursor": ("IDE", "Seguro", "Geralmente cache e dados de editor.", "Pode mover para a Lixeira com segurança na maioria dos casos."),
    "discord": ("Chat", "Seguro", "Cache e mídia local costumam crescer com o tempo.", "Fechar Discord antes de limpar melhora a chance de sucesso."),
    "Notion": ("Produtividade", "Seguro", "Cache offline pode crescer bastante.", "Fechar Notion antes de limpar melhora a chance de sucesso."),
    "OpenEmu": ("Emulação", "Revisar", "Pode conter ROMs, saves e BIOS.", "Revisar manualmente antes de excluir."),
    "Docker": ("Dev", "Revisar", "Pode incluir imagens, volumes e containers.", "Fechar Docker Desktop ou usar docker system prune."),
    "Android": ("Dev", "Revisar", "Pode conter SDK, AVD e builds.", "Revisar se há emuladores ou SDKs necessários."),
    "pyinstaller": ("Dev", "Seguro", "Artefatos de build antigos.", "Pode mover para a Lixeira com segurança na maioria dos casos."),
    "minecraft": ("Jogos", "Revisar", "Pode conter mundos e mods do usuário.", "Revisar manualmente antes de excluir."),
    "com.apple.wallpaper": ("Sistema", "Seguro", "Cache local de wallpapers.", "Pode mover para a Lixeira com segurança na maioria dos casos."),
    "Telegram": ("Chat", "Revisar", "Pode conter mídia baixada localmente.", "Fechar Telegram antes de limpar."),
    "WhatsApp": ("Chat", "Revisar", "Pode conter mídia e sessão local.", "Fechar WhatsApp antes de limpar."),
}


def classify(path: Path) -> tuple[str, str, str, str]:
    name = path.name
    for key, value in RULES.items():
        if key.lower() in name.lower():
            return value

    lowered = str(path).lower()
    if "cache" in lowered or "logs" in lowered:
        return ("Cache/Logs", "Seguro", "Itens geralmente recuperáveis.", "Pode mover para a Lixeira com segurança na maioria dos casos.")
    if "container" in lowered:
        return ("Containers", "Revisar", "Pode conter dados persistidos de apps.", "Pode exigir fechar o app relacionado e dar Acesso Total ao Disco.")
    if lowered.endswith(".photoslibrary"):
        return ("Fotos", "Revisar", "Biblioteca de fotos local do macOS.", "Revisar manualmente antes de excluir.")
    return ("Outros", "Revisar", "Revisar antes de limpar.", "Validar antes de remover.")


class SizeTableWidgetItem(QTableWidgetItem):
    def __init__(self, size_bytes: int):
        super().__init__(format_bytes(size_bytes))
        self.size_bytes = size_bytes
        self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

    def __lt__(self, other):
        if isinstance(other, SizeTableWidgetItem):
            return self.size_bytes < other.size_bytes
        return super().__lt__(other)


class ScannerThread(QThread):
    progress = Signal(int)
    finished_scan = Signal(list)
    failed = Signal(str)

    def __init__(self, targets: Iterable[Path]):
        super().__init__()
        self.targets = [t for t in targets if t.exists()]

    def run(self) -> None:
        try:
            results: list[ScanResult] = []
            if not self.targets:
                self.finished_scan.emit(results)
                return

            total = len(self.targets)
            for index, target in enumerate(self.targets, start=1):
                for child in self.safe_iterdir(target):
                    size = self.get_size(child)
                    category, safety, note, action_hint = classify(child)
                    results.append(
                        ScanResult(
                            path=child,
                            size_bytes=size,
                            category=category,
                            safety=safety,
                            note=note,
                            action_hint=action_hint,
                        )
                    )
                self.progress.emit(int(index / total * 100))

            results.sort(key=lambda item: item.size_bytes, reverse=True)
            self.finished_scan.emit(results)
        except Exception as exc:
            self.failed.emit(str(exc))

    def safe_iterdir(self, path: Path) -> Iterable[Path]:
        try:
            yield from path.iterdir()
        except (PermissionError, FileNotFoundError):
            return

    def get_size(self, path: Path) -> int:
        try:
            if path.is_symlink():
                return 0
            if path.is_file():
                return path.stat().st_size

            total = 0
            for root, dirs, files in os.walk(path, onerror=lambda e: None):
                dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
                for file_name in files:
                    file_path = Path(root) / file_name
                    try:
                        if not file_path.is_symlink():
                            total += file_path.stat().st_size
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
            return total
        except (PermissionError, FileNotFoundError, OSError):
            return 0


class StatCard(QFrame):
    def __init__(self, title: str, value: str, subtitle: str = ""):
        super().__init__()
        self.setObjectName("statCard")

        self.title_label = QLabel(title)
        self.title_label.setObjectName("cardTitle")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("cardValue")

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("cardSubtitle")
        self.subtitle_label.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(6)
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)

    def update_content(self, value: str, subtitle: str = "") -> None:
        self.value_label.setText(value)
        self.subtitle_label.setText(subtitle)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1280, 780)
        self.results: list[ScanResult] = []
        self.filtered_results: list[ScanResult] = []
        self.thread: ScannerThread | None = None

        self.status_label = QLabel("Pronto para escanear.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)

        self.total_card = StatCard("Espaço analisado", "0 B", "Volume dos itens exibidos no resultado atual.")
        self.safe_card = StatCard("Recuperável com segurança", "0 B", "Itens marcados como seguros para mover à Lixeira.")
        self.review_card = StatCard("Revisar antes", "0 B", "Itens que podem exigir conferência ou fechamento do app.")
        self.items_card = StatCard("Itens encontrados", "0", "Quantidade de entradas no resultado atual.")

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)
        cards_layout.addWidget(self.total_card)
        cards_layout.addWidget(self.safe_card)
        cards_layout.addWidget(self.review_card)
        cards_layout.addWidget(self.items_card)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar por nome, caminho ou app...")
        self.search_input.textChanged.connect(self.apply_filters)

        self.safety_filter = QComboBox()
        self.safety_filter.addItems(["Todos", "Seguro", "Revisar"])
        self.safety_filter.currentTextChanged.connect(self.apply_filters)

        self.category_filter = QComboBox()
        self.category_filter.addItem("Todas")
        self.category_filter.currentTextChanged.connect(self.apply_filters)

        self.size_filter = QComboBox()
        self.size_filter.addItems(["Todos", "> 100 MB", "> 500 MB", "> 1 GB", "> 5 GB"])
        self.size_filter.currentTextChanged.connect(self.apply_filters)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Pasta", "Tamanho", "Categoria", "Segurança", "Observação", "Ação sugerida"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setColumnWidth(0, 460)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 110)
        self.table.setColumnWidth(3, 90)
        self.table.setColumnWidth(4, 230)

        scan_button = QPushButton("Escanear áreas padrão")
        scan_button.clicked.connect(self.start_default_scan)

        custom_button = QPushButton("Escanear outra pasta")
        custom_button.clicked.connect(self.scan_custom_folder)

        reveal_button = QPushButton("Abrir no Finder")
        reveal_button.clicked.connect(self.reveal_selected)

        trash_button = QPushButton("Mover para Lixeira")
        trash_button.clicked.connect(self.trash_selected)

        smart_clean_button = QPushButton("Limpeza Inteligente")
        smart_clean_button.setObjectName("primaryButton")
        smart_clean_button.clicked.connect(self.smart_clean_safe_items)

        top_bar = QHBoxLayout()
        top_bar.addWidget(scan_button)
        top_bar.addWidget(custom_button)
        top_bar.addStretch()
        top_bar.addWidget(reveal_button)
        top_bar.addWidget(trash_button)
        top_bar.addWidget(smart_clean_button)

        filters_bar = QHBoxLayout()
        filters_bar.addWidget(QLabel("Busca:"))
        filters_bar.addWidget(self.search_input, 2)
        filters_bar.addWidget(QLabel("Segurança:"))
        filters_bar.addWidget(self.safety_filter)
        filters_bar.addWidget(QLabel("Categoria:"))
        filters_bar.addWidget(self.category_filter)
        filters_bar.addWidget(QLabel("Tamanho:"))
        filters_bar.addWidget(self.size_filter)

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addLayout(top_bar)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress)
        layout.addLayout(cards_layout)
        layout.addLayout(filters_bar)
        layout.addWidget(self.table)
        self.setCentralWidget(root)

        exit_action = QAction("Sair", self)
        exit_action.triggered.connect(self.close)
        self.menuBar().addAction(exit_action)

        self.apply_styles()

    def apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background-color: #1f1f1f;
                color: #f2f2f2;
                font-size: 13px;
            }
            QPushButton {
                background-color: #3a3a3a;
                border: 1px solid #4b4b4b;
                border-radius: 10px;
                padding: 9px 14px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QPushButton#primaryButton {
                background-color: #0a84ff;
                border: 1px solid #0a84ff;
                font-weight: 600;
            }
            QPushButton#primaryButton:hover {
                background-color: #2d95ff;
            }
            QLineEdit, QComboBox {
                background-color: #2a2a2a;
                border: 1px solid #4b4b4b;
                border-radius: 10px;
                padding: 8px 10px;
                min-height: 18px;
            }
            QProgressBar {
                background-color: #2a2a2a;
                border: none;
                border-radius: 6px;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #0a84ff;
                border-radius: 6px;
            }
            QTableWidget {
                background-color: #151515;
                alternate-background-color: #1b1b1b;
                gridline-color: #2d2d2d;
                border: 1px solid #333333;
                border-radius: 12px;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #f2f2f2;
                padding: 8px;
                border: none;
                border-right: 1px solid #3c3c3c;
                font-weight: 600;
            }
            QFrame#statCard {
                background-color: #2a2a2a;
                border: 1px solid #353535;
                border-radius: 16px;
            }
            QLabel#cardTitle {
                color: #a0a0a0;
                font-size: 12px;
            }
            QLabel#cardValue {
                font-size: 24px;
                font-weight: 700;
            }
            QLabel#cardSubtitle {
                color: #b5b5b5;
                font-size: 12px;
            }
            """
        )

    def start_default_scan(self) -> None:
        self.start_scan(DEFAULT_SCAN_TARGETS)

    def scan_custom_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Escolha a pasta para escanear")
        if selected:
            self.start_scan([Path(selected)])

    def start_scan(self, targets: list[Path]) -> None:
        self.progress.setValue(0)
        self.status_label.setText("Escaneando...")
        self.table.setRowCount(0)
        self.results = []
        self.filtered_results = []
        self.total_card.update_content("0 B")
        self.safe_card.update_content("0 B")
        self.review_card.update_content("0 B")
        self.items_card.update_content("0")

        self.thread = ScannerThread(targets)
        self.thread.progress.connect(self.progress.setValue)
        self.thread.finished_scan.connect(self.populate_results)
        self.thread.failed.connect(self.show_error)
        self.thread.start()

    def populate_results(self, results: list[ScanResult]) -> None:
        self.results = results
        self.refresh_category_filter()
        self.apply_filters()
        self.progress.setValue(100)

    def refresh_category_filter(self) -> None:
        current = self.category_filter.currentText()
        categories = sorted({item.category for item in self.results})

        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItem("Todas")
        self.category_filter.addItems(categories)
        if current in categories or current == "Todas":
            self.category_filter.setCurrentText(current)
        self.category_filter.blockSignals(False)

    def apply_filters(self) -> None:
        text = self.search_input.text().strip().lower()
        safety = self.safety_filter.currentText()
        category = self.category_filter.currentText()
        size_filter = self.size_filter.currentText()

        min_bytes = 0
        if size_filter == "> 100 MB":
            min_bytes = 100 * 1024 * 1024
        elif size_filter == "> 500 MB":
            min_bytes = 500 * 1024 * 1024
        elif size_filter == "> 1 GB":
            min_bytes = 1024 * 1024 * 1024
        elif size_filter == "> 5 GB":
            min_bytes = 5 * 1024 * 1024 * 1024

        filtered: list[ScanResult] = []
        for item in self.results:
            haystack = f"{item.path} {item.category} {item.note} {item.action_hint}".lower()
            if text and text not in haystack:
                continue
            if safety != "Todos" and item.safety != safety:
                continue
            if category != "Todas" and item.category != category:
                continue
            if item.size_bytes < min_bytes:
                continue
            filtered.append(item)

        self.filtered_results = filtered
        self.populate_table(filtered)
        self.update_summary_cards(filtered)

    def populate_table(self, results: list[ScanResult]) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(results))

        for row, item in enumerate(results):
            self.table.setItem(row, 0, QTableWidgetItem(str(item.path)))
            self.table.setItem(row, 1, SizeTableWidgetItem(item.size_bytes))
            self.table.setItem(row, 2, QTableWidgetItem(item.category))
            self.table.setItem(row, 3, QTableWidgetItem(item.safety))
            self.table.setItem(row, 4, QTableWidgetItem(item.note))
            self.table.setItem(row, 5, QTableWidgetItem(item.action_hint))
            self.apply_row_colors(row, item.safety)

        self.table.setSortingEnabled(True)
        self.table.sortItems(1, Qt.DescendingOrder)

        total_space = sum(x.size_bytes for x in results)
        self.status_label.setText(
            f"Escaneamento concluído. {len(results)} itens encontrados | Total analisado: {format_bytes(total_space)}"
        )

    def apply_row_colors(self, row: int, safety: str) -> None:
        if safety == "Seguro":
            color = QColor(25, 80, 45, 120)
        elif safety == "Revisar":
            color = QColor(95, 75, 10, 120)
        else:
            color = QColor(80, 30, 30, 120)

        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(color)

    def update_summary_cards(self, results: list[ScanResult]) -> None:
        total = sum(item.size_bytes for item in results)
        safe_items = [item for item in results if item.safety == "Seguro"]
        review_items = [item for item in results if item.safety == "Revisar"]
        safe_total = sum(item.size_bytes for item in safe_items)
        review_total = sum(item.size_bytes for item in review_items)

        self.total_card.update_content(format_bytes(total), "Volume total dos itens exibidos atualmente.")
        self.safe_card.update_content(format_bytes(safe_total), f"{len(safe_items)} itens podem ir para a Lixeira com baixo risco.")
        self.review_card.update_content(format_bytes(review_total), f"{len(review_items)} itens merecem conferência antes da limpeza.")
        self.items_card.update_content(str(len(results)), "Quantidade de entradas após filtros aplicados.")

    def selected_result(self) -> ScanResult | None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, APP_NAME, "Selecione uma linha primeiro.")
            return None
        row = selected[0].row()
        size_item = self.table.item(row, 0)
        if not size_item:
            return None
        selected_path = size_item.text()
        for item in self.filtered_results:
            if str(item.path) == selected_path:
                return item
        return None

    def reveal_selected(self) -> None:
        item = self.selected_result()
        if not item:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(item.path)))

    def smart_clean_safe_items(self) -> None:
        if send2trash is None:
            QMessageBox.warning(self, APP_NAME, "Instale a biblioteca send2trash com: pip install send2trash")
            return

        targets = [item for item in self.filtered_results if item.safety == "Seguro"]
        if not targets:
            QMessageBox.information(self, APP_NAME, "Não há itens seguros no filtro atual.")
            return

        total = sum(item.size_bytes for item in targets)
        answer = QMessageBox.question(
            self,
            APP_NAME,
            f"Mover {len(targets)} itens seguros para a Lixeira?\n\nEspaço estimado: {format_bytes(total)}",
        )
        if answer != QMessageBox.Yes:
            return

        moved = 0
        failed = 0
        for item in targets:
            try:
                send2trash(str(item.path))
                moved += 1
            except Exception:
                failed += 1

        QMessageBox.information(
            self,
            APP_NAME,
            f"Limpeza concluída.\nItens movidos: {moved}\nFalhas: {failed}",
        )
        self.start_default_scan()

    def trash_selected(self) -> None:
        item = self.selected_result()
        if not item:
            return

        if send2trash is None:
            QMessageBox.warning(
                self,
                APP_NAME,
                "A biblioteca send2trash não está instalada. Instale com: pip install send2trash",
            )
            return

        question = f"Mover para a Lixeira?\n\n{item.path}"
        if item.safety == "Revisar":
            question += "\n\nEsse item está marcado como 'Revisar'."
        answer = QMessageBox.question(self, APP_NAME, question)
        if answer != QMessageBox.Yes:
            return

        try:
            send2trash(str(item.path))
            QMessageBox.information(self, APP_NAME, "Item movido para a Lixeira.")
            self.start_default_scan()
        except Exception as exc:
            path_str = str(item.path)
            extra = ""
            if any(hint in path_str for hint in PROTECTED_PATH_HINTS):
                extra = (
                    "\n\nEsse local é protegido pelo macOS."
                    "\nTente fechar o aplicativo relacionado e conceder Acesso Total ao Disco ao VS Code ou Terminal."
                )
            QMessageBox.critical(
                self,
                APP_NAME,
                f"Não foi possível mover para a Lixeira:\n{exc}{extra}",
            )

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, APP_NAME, f"Erro durante o escaneamento:\n{message}")
        self.status_label.setText("Falha ao escanear.")
        self.progress.setValue(0)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
