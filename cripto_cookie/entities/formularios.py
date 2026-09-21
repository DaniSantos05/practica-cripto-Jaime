"""Campos y formularios de autenticación de CryptoNotes."""

from __future__ import annotations

import re

import pygame

from core import settings


class CampoTexto:
    """Campo de una línea con límite, placeholder y modo contraseña."""

    def __init__(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
        placeholder: str = "",
        password: bool = False,
        max_length: int = 254,
    ):
        self.rect = pygame.Rect(x, y, width, height)
        self.placeholder = placeholder
        self.password = password
        self.max_length = max_length
        self.text = ""
        self.active = False
        self.password_visible = False
        self.font = pygame.font.Font(None, 24)
        self.eye_rect = pygame.Rect(self.rect.right - 42, self.rect.y, 42, height)

    def handle_event(self, event: pygame.event.Event) -> str | None:
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.password and self.eye_rect.collidepoint(event.pos):
                self.password_visible = not self.password_visible
                self.active = True
                return None
            self.active = self.rect.collidepoint(event.pos)
        if event.type == pygame.KEYDOWN and self.active:
            if event.key == pygame.K_RETURN:
                return "enter"
            if event.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            elif event.key == pygame.K_ESCAPE:
                self.active = False
            elif (
                event.unicode
                and event.unicode.isprintable()
                and len(self.text) < self.max_length
            ):
                self.text += event.unicode
        return None

    def draw(self, surface: pygame.Surface) -> None:
        border = settings.PRIMARY if self.active else settings.BORDER
        pygame.draw.rect(surface, settings.WHITE, self.rect, border_radius=5)
        pygame.draw.rect(surface, border, self.rect, 2, border_radius=5)
        shown = self.text
        if self.password and not self.password_visible:
            shown = "•" * len(self.text)
        color = settings.TEXT
        if not shown:
            shown, color = self.placeholder, settings.MUTED
        available = self.rect.width - (55 if self.password else 16)
        while shown and self.font.size(shown)[0] > available:
            shown = shown[1:]
        rendered = self.font.render(shown, True, color)
        surface.blit(
            rendered, (self.rect.x + 8, self.rect.centery - rendered.get_height() // 2)
        )
        if self.password:
            label = self.font.render(
                "ver" if not self.password_visible else "oc.", True, settings.PRIMARY
            )
            surface.blit(label, label.get_rect(center=self.eye_rect.center))


class _FormularioBase:
    def __init__(self, screen_width: int, screen_height: int, width: int, height: int):
        self.rect = pygame.Rect(
            (screen_width - width) // 2,
            (screen_height - height) // 2,
            width,
            height,
        )
        self.activo = False
        self.mensaje = ""
        self.mensaje_color = settings.DANGER
        self.title_font = pygame.font.Font(None, 34)
        self.label_font = pygame.font.Font(None, 22)
        self.button_font = pygame.font.Font(None, 24)

    def mostrar(self) -> None:
        self.activo = True
        self.mensaje = ""

    def _draw_window(self, surface: pygame.Surface, title: str) -> None:
        overlay = pygame.Surface(surface.get_size(), pygame.SRCALPHA)
        overlay.fill((15, 23, 42, 155))
        surface.blit(overlay, (0, 0))
        pygame.draw.rect(surface, settings.PANEL, self.rect, border_radius=10)
        pygame.draw.rect(surface, settings.PRIMARY, self.rect, 3, border_radius=10)
        rendered = self.title_font.render(title, True, settings.TEXT)
        surface.blit(
            rendered, rendered.get_rect(centerx=self.rect.centerx, y=self.rect.y + 24)
        )

    def _draw_button(
        self,
        surface: pygame.Surface,
        rect: pygame.Rect,
        text: str,
        color: tuple[int, int, int],
    ) -> None:
        pygame.draw.rect(surface, color, rect, border_radius=5)
        rendered = self.button_font.render(text, True, settings.WHITE)
        surface.blit(rendered, rendered.get_rect(center=rect.center))

    def _draw_message(self, surface: pygame.Surface) -> None:
        if not self.mensaje:
            return
        rendered = self.label_font.render(self.mensaje, True, self.mensaje_color)
        surface.blit(
            rendered,
            rendered.get_rect(centerx=self.rect.centerx, bottom=self.rect.bottom - 18),
        )


class FormularioRegistro(_FormularioBase):
    def __init__(self, screen_width: int, screen_height: int):
        super().__init__(screen_width, screen_height, 540, 480)
        x = self.rect.x + 70
        y = self.rect.y + 90
        width = 400
        self.campo_usuario = CampoTexto(
            x, y, width, 38, "Usuario (3-32 caracteres)", max_length=32
        )
        self.campo_email = CampoTexto(
            x, y + 65, width, 38, "Correo electrónico", max_length=254
        )
        self.campo_password = CampoTexto(
            x, y + 130, width, 38, "Contraseña (mínimo 12)", True, 128
        )
        self.campo_confirmar = CampoTexto(
            x, y + 195, width, 38, "Repetir contraseña", True, 128
        )
        self.boton_registrar = pygame.Rect(x, y + 275, 180, 42)
        self.boton_cancelar = pygame.Rect(x + 220, y + 275, 180, 42)

    @property
    def fields(self) -> tuple[CampoTexto, ...]:
        return (
            self.campo_usuario,
            self.campo_email,
            self.campo_password,
            self.campo_confirmar,
        )

    def ocultar(self) -> None:
        self.activo = False
        self.mensaje = ""
        for field in self.fields:
            field.text = ""

    def handle_event(self, event: pygame.event.Event):
        if not self.activo:
            return None
        enter = any(field.handle_event(event) == "enter" for field in self.fields)
        if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
            self.ocultar()
            return "cancelar"
        if enter:
            return self.procesar_registro()
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.boton_registrar.collidepoint(event.pos):
                return self.procesar_registro()
            if self.boton_cancelar.collidepoint(event.pos):
                self.ocultar()
                return "cancelar"
        return None

    def procesar_registro(self):
        username = self.campo_usuario.text.strip()
        email = self.campo_email.text.strip()
        password = self.campo_password.text
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            self.mensaje = "Usuario inválido: usa letras, números, punto, guion o _"
            return None
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            self.mensaje = "Correo electrónico inválido"
            return None
        if not 12 <= len(password) <= 128:
            self.mensaje = "La contraseña debe tener entre 12 y 128 caracteres"
            return None
        if password != self.campo_confirmar.text:
            self.mensaje = "Las contraseñas no coinciden"
            return None
        self.mensaje = ""
        return (
            "usuario_registrado",
            {"usuario": username, "email": email, "password": password},
        )

    def mostrar_resultado(self, mensaje: str, color: tuple[int, int, int]) -> None:
        self.mensaje, self.mensaje_color = mensaje, color

    def draw(self, surface: pygame.Surface) -> None:
        if not self.activo:
            return
        self._draw_window(surface, "Crear bóveda de notas")
        labels = ("Usuario", "Correo", "Contraseña", "Confirmación")
        for label, field in zip(labels, self.fields):
            rendered = self.label_font.render(label, True, settings.TEXT)
            surface.blit(rendered, (field.rect.x, field.rect.y - 21))
            field.draw(surface)
        self._draw_button(surface, self.boton_registrar, "Registrar", settings.SUCCESS)
        self._draw_button(surface, self.boton_cancelar, "Cancelar", settings.DANGER)
        self._draw_message(surface)


class FormularioLogin(_FormularioBase):
    def __init__(self, screen_width: int, screen_height: int):
        super().__init__(screen_width, screen_height, 480, 330)
        x = self.rect.x + 55
        y = self.rect.y + 95
        self.campo_usuario = CampoTexto(
            x, y, 370, 38, "Usuario o correo", max_length=254
        )
        self.campo_password = CampoTexto(x, y + 70, 370, 38, "Contraseña", True, 128)
        self.boton_login = pygame.Rect(x, y + 140, 165, 42)
        self.boton_cancelar = pygame.Rect(x + 205, y + 140, 165, 42)

    def ocultar(self) -> None:
        self.activo = False
        self.mensaje = ""
        self.campo_usuario.text = ""
        self.campo_password.text = ""

    def handle_event(self, event: pygame.event.Event):
        if not self.activo:
            return None
        enter = self.campo_usuario.handle_event(event) == "enter"
        enter = self.campo_password.handle_event(event) == "enter" or enter
        if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
            self.ocultar()
            return "cancelar"
        if enter:
            return self.procesar_login()
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.boton_login.collidepoint(event.pos):
                return self.procesar_login()
            if self.boton_cancelar.collidepoint(event.pos):
                self.ocultar()
                return "cancelar"
        return None

    def procesar_login(self):
        identifier = self.campo_usuario.text.strip()
        password = self.campo_password.text
        if not identifier or not password:
            self.mensaje = "Introduce usuario y contraseña"
            return None
        return "intento_login", {"usuario": identifier, "password": password}

    def mostrar_resultado_login(self, exitoso: bool, mensaje: str = "") -> None:
        self.mensaje = mensaje or (
            "Acceso correcto" if exitoso else "Credenciales inválidas"
        )
        self.mensaje_color = settings.SUCCESS if exitoso else settings.DANGER
        if not exitoso:
            self.campo_password.text = ""

    def draw(self, surface: pygame.Surface) -> None:
        if not self.activo:
            return
        self._draw_window(surface, "Abrir bóveda")
        for label, field in (
            ("Usuario o correo", self.campo_usuario),
            ("Contraseña", self.campo_password),
        ):
            rendered = self.label_font.render(label, True, settings.TEXT)
            surface.blit(rendered, (field.rect.x, field.rect.y - 21))
            field.draw(surface)
        self._draw_button(surface, self.boton_login, "Entrar", settings.PRIMARY)
        self._draw_button(surface, self.boton_cancelar, "Cancelar", settings.DANGER)
        self._draw_message(surface)
