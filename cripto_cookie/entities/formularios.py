import pygame
import string
from core import settings


class CampoTexto:
    """Un campo de texto editable con placeholder, modo contraseña y ojo."""
    def __init__(self, x, y, width, height, placeholder="", password=False):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = ""
        self.placeholder = placeholder
        self.password = password
        self.font = pygame.font.Font(pygame.font.get_default_font(), 20)
        self.active = False
        
        self.password_visible = False
        self.eye_rect = None
        if self.password:
            self.eye_rect = pygame.Rect(self.rect.right - 32, self.rect.y + 4, 28, self.rect.height - 8)

    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            # Click en el "ojo" para mostrar/ocultar contraseña
            if self.password and self.eye_rect and self.eye_rect.collidepoint(event.pos):
                self.password_visible = not self.password_visible
                self.active = True
                return "eye_toggle" 
            
            # Click en el campo de texto
            self.active = self.rect.collidepoint(event.pos)

        if event.type == pygame.KEYDOWN and self.active:
            if event.key == pygame.K_RETURN:
                return "enter"
            elif event.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            else:
                if len(self.text) < 50: # Límite de 50 caracteres
                    self.text += event.unicode
        return None

    def update(self):
        # Este método ya no es necesario, pero lo mantenemos por si menu.py lo llama
        pass

    def draw(self, surface):
        fill_color = (220, 220, 255) if self.active else settings.WHITE
        pygame.draw.rect(surface, fill_color, self.rect)
        pygame.draw.rect(surface, settings.BLACK, self.rect, 2)

        # Determina qué texto mostrar (placeholder, asteriscos, o texto real)
        display_text = self.text
        if self.password and not self.password_visible and self.text:
            display_text = "*" * len(self.text)
        elif not self.text and not self.active:
            display_text = self.placeholder

        if not self.text and not self.active:
            text_color = settings.GRAY
        else:
            text_color = settings.BLACK
        
        text_surface = self.font.render(display_text, True, text_color)
        text_width = text_surface.get_width()
        padding = 10
        blit_x = self.rect.x + 5
        
        # Define un área de "clip" para que el texto no se salga del campo
        clip_rect = self.rect.inflate(-padding, -padding)
        if self.password and self.eye_rect:
            clip_rect.width -= (self.eye_rect.width - 2)

        # Si el texto es más largo que el campo, lo "desplaza" a la izquierda
        if text_width > clip_rect.width:
            blit_x = clip_rect.right - text_width
        
        # Dibuja el texto solo dentro del área de clip
        old_clip = surface.get_clip()
        surface.set_clip(clip_rect)
        surface.blit(text_surface, (blit_x, self.rect.y + 5))
        surface.set_clip(old_clip)

        # Dibuja el cursor (caret) estático si el campo está activo
        caret_x = blit_x + text_width
        if self.active and clip_rect.collidepoint(caret_x, self.rect.centery):
            pygame.draw.line(surface, settings.BLACK, 
                             (caret_x, self.rect.y + 4), 
                             (caret_x, self.rect.bottom - 4), 1)

        # Dibuja el botón del "ojo"
        if self.password and self.eye_rect:
            eye_char = "O" if self.password_visible else "X"
            eye_color = (210, 210, 210) if self.active else (230, 230, 230)
            pygame.draw.rect(surface, eye_color, self.eye_rect)
            pygame.draw.rect(surface, settings.GRAY, self.eye_rect, 1)
            
            eye_surf = self.font.render(eye_char, True, settings.BLACK)
            eye_rect_surf = eye_surf.get_rect(center=self.eye_rect.center)
            surface.blit(eye_surf, eye_rect_surf)


class FormularioRegistro:
    """Formulario modal para registrar nuevos usuarios."""
    def __init__(self, screen_width, screen_height):
        self.screen_width = screen_width
        self.screen_height = screen_height
        self.width = 450
        self.height = 450 # Más altura para mensajes de error
        
        self.x = (screen_width - self.width) // 2
        self.y = (screen_height - self.height) // 2
        self.rect = pygame.Rect(self.x, self.y, self.width, self.height)
        self.activo = False
        self.mensaje = ""
        self.mensaje_color = settings.BLACK
        self.font_titulo = pygame.font.Font(pygame.font.get_default_font(), 24)
        self.font_boton = pygame.font.Font(pygame.font.get_default_font(), 18)
        
        campo_y = self.y + 80
        self.campo_usuario = CampoTexto(self.x + 75, campo_y, 300, 35, "Nombre de usuario")
        self.campo_email = CampoTexto(self.x + 75, campo_y + 60, 300, 35, "Email")
        self.campo_password = CampoTexto(self.x + 75, campo_y + 120, 300, 35, "Contrasena", True)
        self.campo_confirmar = CampoTexto(self.x + 75, campo_y + 180, 300, 35, "Confirmar contrasena", True)
        
        self.boton_registrar = pygame.Rect(self.x + 75, self.y + 360, 120, 35)
        self.boton_cancelar = pygame.Rect(self.x + 255, self.y + 360, 120, 35)

    def mostrar(self):
        self.activo = True

    def ocultar(self):
        self.activo = False
        self.campo_usuario.text = ""
        self.campo_email.text = ""
        self.campo_password.text = ""
        self.campo_confirmar.text = ""
        self.mensaje = ""

    def handle_event(self, event):
        if not self.activo:
            return None

        self.campo_usuario.handle_event(event)
        self.campo_email.handle_event(event)
        self.campo_password.handle_event(event)
        self.campo_confirmar.handle_event(event)

        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.boton_registrar.collidepoint(event.pos):
                return self.procesar_registro()
            elif self.boton_cancelar.collidepoint(event.pos):
                self.ocultar()
                return "cancelar"
        if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
            self.ocultar()
            return "cancelar"
        return None

    def procesar_registro(self):
        """Valida los campos y devuelve los datos o None si hay error."""
        usuario = self.campo_usuario.text.strip()
        email = self.campo_email.text.strip()
        password = self.campo_password.text
        
        # Validaciones
        if not usuario:
            self.mensaje, self.mensaje_color = "El nombre de usuario es requerido", settings.RED
            return None
        if not email:
            self.mensaje, self.mensaje_color = "El email es requerido", settings.RED
            return None
        if "@" not in email:
            self.mensaje, self.mensaje_color = "El formato del email no es válido", settings.RED
            return None
        
        # Validación de contraseña robusta
        if len(password) < 8:
            self.mensaje, self.mensaje_color = "Contraseña: 8 caracteres mínimo.", settings.RED
            return None
        if not any(c.islower() for c in password):
            self.mensaje, self.mensaje_color = "Contraseña: Mínimo una minúscula.", settings.RED
            return None
        if not any(c.isupper() for c in password):
            self.mensaje, self.mensaje_color = "Contraseña: Mínimo una mayúscula.", settings.RED
            return None
        if not any(c.isdigit() for c in password):
            self.mensaje, self.mensaje_color = "Contraseña: Mínimo un número.", settings.RED
            return None
        if not any(c in set(string.punctuation) for c in password):
            self.mensaje, self.mensaje_color = "Contraseña: Mínimo un caracter especial.", settings.RED
            return None
        if password != self.campo_confirmar.text:
            self.mensaje, self.mensaje_color = "Las contraseñas no coinciden", settings.RED
            return None

        # Si todo está OK
        datos_usuario = {"usuario": usuario, "email": email, "password": password}
        self.mensaje, self.mensaje_color = "", settings.BLACK # Limpia el mensaje
        
        return ("usuario_registrado", datos_usuario)

    def mostrar_resultado(self, mensaje, color):
        """Usado por core.py para mostrar el resultado de la llamada al servidor."""
        self.mensaje = mensaje
        self.mensaje_color = color
        if color == settings.GREEN: # Limpia campos si el registro es exitoso
            self.campo_usuario.text = ""
            self.campo_email.text = ""
            self.campo_password.text = ""
            self.campo_confirmar.text = ""

    def update(self):
        pass # No se necesita update

    def draw(self, surface):
        if not self.activo:
            return
        
        # Fondo oscuro semi-transparente
        overlay = pygame.Surface((surface.get_width(), surface.get_height()), pygame.SRCALPHA)
        overlay.fill((0, 0, 0, 128))
        surface.blit(overlay, (0, 0))

        # Ventana del formulario
        pygame.draw.rect(surface, settings.WHITE, self.rect)
        pygame.draw.rect(surface, settings.BLACK, self.rect, 3)

        # Título
        titulo_surface = self.font_titulo.render("Registro de Usuario", True, settings.BLACK)
        titulo_rect = titulo_surface.get_rect(centerx=self.rect.centerx, y=self.rect.y + 30)
        surface.blit(titulo_surface, titulo_rect)

        # Campos de texto
        self.campo_usuario.draw(surface)
        self.campo_email.draw(surface)
        self.campo_password.draw(surface)
        self.campo_confirmar.draw(surface)

        # Botones
        pygame.draw.rect(surface, settings.GREEN, self.boton_registrar)
        pygame.draw.rect(surface, settings.RED, self.boton_cancelar)
        pygame.draw.rect(surface, settings.BLACK, self.boton_registrar, 2)
        pygame.draw.rect(surface, settings.BLACK, self.boton_cancelar, 2)
        
        texto_registrar = self.font_boton.render("Registrar", True, settings.WHITE)
        texto_cancelar = self.font_boton.render("Cancelar", True, settings.WHITE)
        surface.blit(texto_registrar, texto_registrar.get_rect(center=self.boton_registrar.center))
        surface.blit(texto_cancelar, texto_cancelar.get_rect(center=self.boton_cancelar.center))

        # Mensaje de estado/error
        if self.mensaje:
            mensaje_surface = self.font_boton.render(self.mensaje, True, self.mensaje_color)
            mensaje_rect = mensaje_surface.get_rect(centerx=self.rect.centerx, y=self.rect.bottom - 40)
            surface.blit(mensaje_surface, mensaje_rect)


class FormularioLogin:
    """Formulario modal para iniciar sesión."""
    def __init__(self, screen_width, screen_height):
        self.screen_width = screen_width
        self.screen_height = screen_height
        self.width = 400
        self.height = 300
        self.x = (screen_width - self.width) // 2
        self.y = (screen_height - self.height) // 2
        self.rect = pygame.Rect(self.x, self.y, self.width, self.height)
        self.activo = False
        self.mensaje = ""
        self.mensaje_color = settings.BLACK
        self.font_titulo = pygame.font.Font(pygame.font.get_default_font(), 24)
        self.font_boton = pygame.font.Font(pygame.font.get_default_font(), 18)
        
        campo_y = self.y + 80
        self.campo_usuario = CampoTexto(self.x + 50, campo_y, 300, 30, "Nombre de usuario o email")
        self.campo_password = CampoTexto(self.x + 50, campo_y + 50, 300, 30, "Contrasena", True)
        
        self.boton_login = pygame.Rect(self.x + 60, self.y + 200, 120, 35)
        self.boton_cancelar = pygame.Rect(self.x + 220, self.y + 200, 120, 35)

    def mostrar(self):
        self.activo = True

    def ocultar(self):
        self.activo = False
        self.campo_usuario.text = ""
        self.campo_password.text = ""
        self.mensaje = ""

    def handle_event(self, event):
        if not self.activo:
            return None

        resultado_usuario = self.campo_usuario.handle_event(event)
        resultado_password = self.campo_password.handle_event(event)

        if resultado_usuario == "enter" or resultado_password == "enter":
            return self.procesar_login()

        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.boton_login.collidepoint(event.pos):
                return self.procesar_login()
            elif self.boton_cancelar.collidepoint(event.pos):
                self.ocultar()
                return "cancelar"
        if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
            self.ocultar()
            return "cancelar"
        return None

    def procesar_login(self):
        """Valida los campos y devuelve los datos para el login."""
        if not self.campo_usuario.text.strip():
            self.mensaje, self.mensaje_color = "El usuario/email es requerido", settings.RED
            return None
        if not self.campo_password.text:
            self.mensaje, self.mensaje_color = "La contraseña es requerida", settings.RED
            return None

        datos_login = {
            "usuario": self.campo_usuario.text.strip(),
            "password": self.campo_password.text
        }
        
        self.mensaje, self.mensaje_color = "", settings.BLACK # Limpia el mensaje
        return ("intento_login", datos_login)

    def mostrar_resultado_login(self, exitoso, mensaje=""):
        """Usado por core.py para mostrar el resultado de la llamada al servidor."""
        if exitoso:
            self.mensaje = "¡Login exitoso!"
            self.mensaje_color = settings.GREEN
            self.campo_usuario.text = ""
            self.campo_password.text = ""
        else:
            self.mensaje = mensaje or "Usuario o contraseña incorrectos"
            self.mensaje_color = settings.RED
            self.campo_password.text = "" # Borra solo la contraseña

    def update(self):
        pass # No se necesita update

    def draw(self, surface):
        if not self.activo:
            return

        # Fondo oscuro
        overlay = pygame.Surface((surface.get_width(), surface.get_height()), pygame.SRCALPHA)
        overlay.fill((0, 0, 0, 128))
        surface.blit(overlay, (0, 0))

        # Ventana
        pygame.draw.rect(surface, settings.WHITE, self.rect)
        pygame.draw.rect(surface, settings.BLACK, self.rect, 3)

        # Título
        titulo_surface = self.font_titulo.render("Iniciar Sesion", True, settings.BLACK)
        titulo_rect = titulo_surface.get_rect(centerx=self.rect.centerx, y=self.rect.y + 30)
        surface.blit(titulo_surface, titulo_rect)

        # Campos
        self.campo_usuario.draw(surface)
        self.campo_password.draw(surface)

        # Botones
        pygame.draw.rect(surface, settings.BLUE, self.boton_login)
        pygame.draw.rect(surface, settings.RED, self.boton_cancelar)
        pygame.draw.rect(surface, settings.BLACK, self.boton_login, 2)
        pygame.draw.rect(surface, settings.BLACK, self.boton_cancelar, 2)
        
        texto_login = self.font_boton.render("Entrar", True, settings.WHITE)
        texto_cancelar = self.font_boton.render("Cancelar", True, settings.WHITE)
        surface.blit(texto_login, texto_login.get_rect(center=self.boton_login.center))
        surface.blit(texto_cancelar, texto_cancelar.get_rect(center=self.boton_cancelar.center))

        # Mensaje de estado/error
        if self.mensaje:
            mensaje_surface = self.font_boton.render(self.mensaje, True, self.mensaje_color)
            mensaje_rect = mensaje_surface.get_rect(centerx=self.rect.centerx, y=self.rect.bottom - 50)
            surface.blit(mensaje_surface, mensaje_rect)