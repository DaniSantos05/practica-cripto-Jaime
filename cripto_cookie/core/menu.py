"""Interfaz Pygame para listar y editar notas de texto."""

from __future__ import annotations

import textwrap

import pygame

from core import settings
from core.crypto_utils import MAX_NOTE_CONTENT, MAX_NOTE_TITLE
from entities.formularios import CampoTexto, FormularioLogin, FormularioRegistro


class Boton:
    def __init__(
        self,
        rect: pygame.Rect,
        text: str,
        color: tuple[int, int, int] = settings.PRIMARY,
    ):
        self.rect = rect
        self.text = text
        self.color = color
        self.hovered = False
        self.font = pygame.font.Font(None, 23)

    def handle_event(self, event: pygame.event.Event) -> bool:
        if event.type == pygame.MOUSEMOTION:
            self.hovered = self.rect.collidepoint(event.pos)
        return (
            event.type == pygame.MOUSEBUTTONDOWN
            and event.button == 1
            and self.rect.collidepoint(event.pos)
        )

    def draw(self, surface: pygame.Surface, text: str | None = None) -> None:
        color = (
            tuple(min(255, component + 18) for component in self.color)
            if self.hovered
            else self.color
        )
        pygame.draw.rect(surface, color, self.rect, border_radius=6)
        rendered = self.font.render(text or self.text, True, settings.WHITE)
        surface.blit(rendered, rendered.get_rect(center=self.rect.center))


class EditorMultilinea:
    """Editor sencillo, limitado y desplazable para el cuerpo de una nota."""

    def __init__(self, rect: pygame.Rect):
        self.rect = rect
        self.text = ""
        self.active = False
        self.scroll = 0
        self.font = pygame.font.Font(None, 23)
        self.line_height = 24

    def handle_event(self, event: pygame.event.Event) -> str | None:
        if event.type == pygame.MOUSEBUTTONDOWN:
            if event.button == 1:
                self.active = self.rect.collidepoint(event.pos)
            elif self.rect.collidepoint(event.pos) and event.button in {4, 5}:
                self.scroll = max(0, self.scroll + (-3 if event.button == 4 else 3))
        if event.type == pygame.MOUSEWHEEL and self.rect.collidepoint(
            pygame.mouse.get_pos()
        ):
            self.scroll = max(0, self.scroll - event.y * 3)
        if event.type == pygame.KEYDOWN and self.active:
            if event.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            elif event.key == pygame.K_RETURN:
                if event.mod & pygame.KMOD_CTRL:
                    return "save"
                if len(self.text) < MAX_NOTE_CONTENT:
                    self.text += "\n"
            elif event.key == pygame.K_TAB:
                if len(self.text) <= MAX_NOTE_CONTENT - 4:
                    self.text += "    "
            elif event.key == pygame.K_ESCAPE:
                self.active = False
            elif (
                event.unicode
                and event.unicode.isprintable()
                and len(self.text) < MAX_NOTE_CONTENT
            ):
                self.text += event.unicode
        return None

    def _wrapped_lines(self) -> list[str]:
        width_chars = max(10, (self.rect.width - 20) // 11)
        lines: list[str] = []
        for paragraph in self.text.split("\n"):
            wrapped = textwrap.wrap(
                paragraph,
                width=width_chars,
                replace_whitespace=False,
                drop_whitespace=False,
            )
            lines.extend(wrapped or [""])
        return lines

    def draw(self, surface: pygame.Surface) -> None:
        border = settings.PRIMARY if self.active else settings.BORDER
        pygame.draw.rect(surface, settings.WHITE, self.rect, border_radius=5)
        pygame.draw.rect(surface, border, self.rect, 2, border_radius=5)
        previous_clip = surface.get_clip()
        surface.set_clip(self.rect.inflate(-10, -10))
        lines = self._wrapped_lines()
        visible_count = max(1, (self.rect.height - 16) // self.line_height)
        self.scroll = min(self.scroll, max(0, len(lines) - visible_count))
        for index, line in enumerate(lines[self.scroll : self.scroll + visible_count]):
            rendered = self.font.render(line, True, settings.TEXT)
            surface.blit(
                rendered,
                (self.rect.x + 9, self.rect.y + 8 + index * self.line_height),
            )
        if not self.text:
            rendered = self.font.render(
                "Escribe aquí el contenido de la nota...", True, settings.MUTED
            )
            surface.blit(rendered, (self.rect.x + 9, self.rect.y + 8))
        surface.set_clip(previous_clip)


class Menu:
    """Pantalla principal de CryptoNotes y modales de autenticación."""

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.formulario_registro = FormularioRegistro(width, height)
        self.formulario_login = FormularioLogin(width, height)
        self.usuario_logueado = False
        self.nombre_usuario = ""
        self.notas: list[dict[str, str]] = []
        self.nota_seleccionada_id: str | None = None
        self.list_scroll = 0
        self.message = ""
        self.message_color = settings.SUCCESS
        self.message_frames = 0
        self.pending_delete_id: str | None = None
        self.delete_frames = 0

        self.title_font = pygame.font.Font(None, 42)
        self.subtitle_font = pygame.font.Font(None, 27)
        self.normal_font = pygame.font.Font(None, 23)
        self.small_font = pygame.font.Font(None, 19)

        self.boton_registro = Boton(
            pygame.Rect(width // 2 - 210, 420, 190, 48),
            "Crear cuenta",
            settings.SUCCESS,
        )
        self.boton_login = Boton(
            pygame.Rect(width // 2 + 20, 420, 190, 48), "Iniciar sesión"
        )
        self.boton_nueva = Boton(
            pygame.Rect(28, 92, 140, 40), "Nueva nota", settings.SUCCESS
        )
        self.boton_refrescar = Boton(pygame.Rect(178, 92, 115, 40), "Actualizar")
        self.boton_guardar = Boton(
            pygame.Rect(width - 430, height - 68, 130, 40), "Guardar", settings.SUCCESS
        )
        self.boton_eliminar = Boton(
            pygame.Rect(width - 288, height - 68, 130, 40), "Eliminar", settings.DANGER
        )
        self.boton_logout = Boton(
            pygame.Rect(width - 146, 22, 118, 38), "Salir", settings.DANGER
        )

        self.lista_rect = pygame.Rect(28, 145, 300, height - 175)
        self.editor_rect = pygame.Rect(354, 92, width - 382, height - 120)
        self.campo_titulo = CampoTexto(
            self.editor_rect.x + 24,
            self.editor_rect.y + 65,
            self.editor_rect.width - 48,
            42,
            "Título de la nota",
            max_length=MAX_NOTE_TITLE,
        )
        self.editor_contenido = EditorMultilinea(
            pygame.Rect(
                self.editor_rect.x + 24,
                self.editor_rect.y + 135,
                self.editor_rect.width - 48,
                self.editor_rect.height - 230,
            )
        )

    def show_message(
        self, message: str, color: tuple[int, int, int] = settings.SUCCESS
    ) -> None:
        self.message = message
        self.message_color = color
        self.message_frames = 240

    def login_usuario(self, username: str, notes: list[dict[str, str]]) -> None:
        self.usuario_logueado = True
        self.nombre_usuario = username
        self.formulario_login.ocultar()
        self.formulario_registro.ocultar()
        self.set_notas(notes)

    def logout_usuario(self) -> None:
        self.usuario_logueado = False
        self.nombre_usuario = ""
        self.notas = []
        self.nota_seleccionada_id = None
        self._clear_editor()

    def set_notas(self, notes: list[dict[str, str]]) -> None:
        previous = self.nota_seleccionada_id
        self.notas = notes
        if previous and any(note["id"] == previous for note in notes):
            self._select_note(previous)
        elif notes:
            self._select_note(notes[0]["id"])
        else:
            self._clear_editor()

    def _clear_editor(self) -> None:
        self.nota_seleccionada_id = None
        self.campo_titulo.text = ""
        self.editor_contenido.text = ""
        self.editor_contenido.scroll = 0
        self.pending_delete_id = None

    def _select_note(self, note_id: str) -> None:
        note = next((item for item in self.notas if item["id"] == note_id), None)
        if note is None:
            return
        self.nota_seleccionada_id = note_id
        self.campo_titulo.text = note["title"]
        self.editor_contenido.text = note["content"]
        self.editor_contenido.scroll = 0
        self.pending_delete_id = None

    def update(self) -> None:
        if self.message_frames > 0:
            self.message_frames -= 1
        if self.delete_frames > 0:
            self.delete_frames -= 1
            if self.delete_frames == 0:
                self.pending_delete_id = None

    def _visible_notes(self) -> list[dict[str, str]]:
        item_height = 64
        count = max(1, self.lista_rect.height // item_height)
        max_scroll = max(0, len(self.notas) - count)
        self.list_scroll = min(max(0, self.list_scroll), max_scroll)
        return self.notas[self.list_scroll : self.list_scroll + count]

    def handle_event(self, event: pygame.event.Event):
        if self.formulario_registro.activo:
            return self.formulario_registro.handle_event(event)
        if self.formulario_login.activo:
            return self.formulario_login.handle_event(event)

        if not self.usuario_logueado:
            if self.boton_registro.handle_event(event):
                self.formulario_registro.mostrar()
            elif self.boton_login.handle_event(event):
                self.formulario_login.mostrar()
            return None

        if self.boton_logout.handle_event(event):
            return "logout"
        if self.boton_nueva.handle_event(event):
            self._clear_editor()
            self.campo_titulo.active = True
            return None
        if self.boton_refrescar.handle_event(event):
            return "refrescar"
        if self.boton_guardar.handle_event(event):
            return (
                "guardar_nota",
                {
                    "id": self.nota_seleccionada_id,
                    "title": self.campo_titulo.text,
                    "content": self.editor_contenido.text,
                },
            )
        if self.boton_eliminar.handle_event(event):
            if self.nota_seleccionada_id is None:
                self.show_message("Selecciona una nota para eliminar", settings.WARNING)
                return None
            if self.pending_delete_id == self.nota_seleccionada_id:
                note_id = self.nota_seleccionada_id
                self.pending_delete_id = None
                return "eliminar_nota", note_id
            self.pending_delete_id = self.nota_seleccionada_id
            self.delete_frames = 180
            self.show_message(
                "Pulsa Eliminar otra vez para confirmar", settings.WARNING
            )
            return None

        if event.type == pygame.MOUSEWHEEL and self.lista_rect.collidepoint(
            pygame.mouse.get_pos()
        ):
            self.list_scroll -= event.y
        if (
            event.type == pygame.MOUSEBUTTONDOWN
            and event.button == 1
            and self.lista_rect.collidepoint(event.pos)
        ):
            index = (event.pos[1] - self.lista_rect.y) // 64
            visible = self._visible_notes()
            if 0 <= index < len(visible):
                self._select_note(visible[index]["id"])

        title_result = self.campo_titulo.handle_event(event)
        body_result = self.editor_contenido.handle_event(event)
        if title_result == "enter" or body_result == "save":
            return (
                "guardar_nota",
                {
                    "id": self.nota_seleccionada_id,
                    "title": self.campo_titulo.text,
                    "content": self.editor_contenido.text,
                },
            )
        return None

    def draw(self, surface: pygame.Surface) -> None:
        surface.fill(settings.BACKGROUND)
        if self.usuario_logueado:
            self._draw_authenticated(surface)
        else:
            self._draw_welcome(surface)
        self.formulario_registro.draw(surface)
        self.formulario_login.draw(surface)

    def _draw_welcome(self, surface: pygame.Surface) -> None:
        card = pygame.Rect(self.width // 2 - 330, 125, 660, 420)
        pygame.draw.rect(surface, settings.PANEL, card, border_radius=14)
        pygame.draw.rect(surface, settings.PRIMARY, card, 3, border_radius=14)
        title = self.title_font.render("CryptoNotes", True, settings.TEXT)
        surface.blit(title, title.get_rect(centerx=card.centerx, y=175))
        subtitle = self.subtitle_font.render(
            "Notas cifradas en el cliente y durante el transporte", True, settings.MUTED
        )
        surface.blit(subtitle, subtitle.get_rect(centerx=card.centerx, y=235))
        descriptions = (
            "AES-256-GCM para confidencialidad e integridad",
            "scrypt para proteger contraseñas y la clave de la bóveda",
            "RSA-PSS y PKI para autenticar al servidor",
            "Protección frente a mensajes manipulados y repetidos",
        )
        for index, description in enumerate(descriptions):
            rendered = self.normal_font.render(f"• {description}", True, settings.TEXT)
            surface.blit(rendered, (card.x + 90, 295 + index * 31))
        self.boton_registro.draw(surface)
        self.boton_login.draw(surface)

    def _draw_authenticated(self, surface: pygame.Surface) -> None:
        header = pygame.Rect(0, 0, self.width, 76)
        pygame.draw.rect(surface, settings.PANEL, header)
        pygame.draw.line(surface, settings.BORDER, (0, 75), (self.width, 75), 1)
        title = self.title_font.render("CryptoNotes", True, settings.TEXT)
        surface.blit(title, (28, 20))
        user = self.normal_font.render(
            f"Bóveda de {self.nombre_usuario}", True, settings.MUTED
        )
        surface.blit(user, (225, 31))
        self.boton_logout.draw(surface)
        self.boton_nueva.draw(surface)
        self.boton_refrescar.draw(surface)

        pygame.draw.rect(surface, settings.PANEL, self.lista_rect, border_radius=8)
        pygame.draw.rect(surface, settings.BORDER, self.lista_rect, 1, border_radius=8)
        visible = self._visible_notes()
        for index, note in enumerate(visible):
            item = pygame.Rect(
                self.lista_rect.x + 4,
                self.lista_rect.y + index * 64 + 4,
                self.lista_rect.width - 8,
                56,
            )
            color = (
                settings.SELECTION
                if note["id"] == self.nota_seleccionada_id
                else settings.PANEL_ALT
            )
            pygame.draw.rect(surface, color, item, border_radius=5)
            title_text = note["title"][:31]
            title_rendered = self.normal_font.render(title_text, True, settings.TEXT)
            surface.blit(title_rendered, (item.x + 10, item.y + 8))
            date_rendered = self.small_font.render(
                note.get("updated_at", "")[:16].replace("T", " "), True, settings.MUTED
            )
            surface.blit(date_rendered, (item.x + 10, item.y + 33))
        if not self.notas:
            empty = self.normal_font.render(
                "Todavía no hay notas", True, settings.MUTED
            )
            surface.blit(empty, empty.get_rect(center=self.lista_rect.center))

        pygame.draw.rect(surface, settings.PANEL, self.editor_rect, border_radius=8)
        pygame.draw.rect(surface, settings.BORDER, self.editor_rect, 1, border_radius=8)
        heading = "Editar nota" if self.nota_seleccionada_id else "Nueva nota"
        rendered_heading = self.subtitle_font.render(heading, True, settings.TEXT)
        surface.blit(
            rendered_heading, (self.editor_rect.x + 24, self.editor_rect.y + 22)
        )
        self.campo_titulo.draw(surface)
        self.editor_contenido.draw(surface)
        counter = self.small_font.render(
            f"{len(self.editor_contenido.text)}/{MAX_NOTE_CONTENT} caracteres",
            True,
            settings.MUTED,
        )
        surface.blit(
            counter,
            (self.editor_contenido.rect.x, self.editor_contenido.rect.bottom + 8),
        )
        self.boton_guardar.draw(surface)
        delete_label = "Confirmar" if self.pending_delete_id else "Eliminar"
        self.boton_eliminar.draw(surface, delete_label)

        if self.message_frames > 0 and self.message:
            rendered = self.normal_font.render(self.message, True, self.message_color)
            surface.blit(rendered, (354, self.height - 55))
