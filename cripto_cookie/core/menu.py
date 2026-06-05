import pygame
from core import settings
from entities.formularios import FormularioRegistro, FormularioLogin

class Mejora:
    """Clase para representar una mejora/upgrade del juego"""
    def __init__(self, nombre, descripcion, precio_base, multiplicador_precio, efecto_tipo, efecto_valor):
        self.nombre = nombre
        self.descripcion = descripcion
        self.precio_base = precio_base
        self.multiplicador_precio = multiplicador_precio
        self.efecto_tipo = efecto_tipo  # "click_power" o "auto_click"
        self.efecto_valor = efecto_valor
        self.nivel = 0
    
    def get_precio_actual(self):
        """Calcular el precio actual basado en el nivel"""
        return int(self.precio_base * (self.multiplicador_precio ** self.nivel))
    
    def get_efecto_total(self):
        """Calcular el efecto total actual"""
        return self.efecto_valor * self.nivel
    
    def to_dict(self):
        """Convertir a diccionario para guardar en JSON"""
        return {
            "nombre": self.nombre,
            "nivel": self.nivel
        }
    
    def from_dict(self, data:dict):
        """Cargar desde diccionario del JSON"""
        self.nivel = data["nivel"]

class Boton:
    def __init__(self, x, y, width, height, text, color=settings.GRAY, text_color=settings.BLACK):
        self.rect = pygame.Rect(x, y, width, height)
        self.color = color
        self.hover_color = (min(255, color[0] + 30), min(255, color[1] + 30), min(255, color[2] + 30))
        self.text_color = text_color
        self.text = text
        self.font = pygame.font.Font(pygame.font.get_default_font(), 18)
        self.is_hovered = False
        
    def handle_event(self, event):
        if event.type == pygame.MOUSEMOTION:
            self.is_hovered = self.rect.collidepoint(event.pos)
        elif event.type == pygame.MOUSEBUTTONDOWN:
            if self.rect.collidepoint(event.pos):
                return True
        return False
    
    def draw(self, surface):
        if self.is_hovered:
            color = self.hover_color
        else:
            color = self.color
        pygame.draw.rect(surface, color, self.rect)
        pygame.draw.rect(surface, settings.BLACK, self.rect, 2)
        
        text_surf = self.font.render(self.text, True, self.text_color)
        text_rect = text_surf.get_rect(center=self.rect.center)
        surface.blit(text_surf, text_rect)

class Menu:
    """Menu unificado que incluye tienda, usuario y premium store"""
    
    def __init__(self, width, height):
        self.width = width
        self.height = height
        
        # ===== CONFIGURACIÓN DE LAYOUT =====
        self.tienda_x = 500
        self.tienda_y = 10
        self.tienda_width = 420
        self.tienda_height = height - 20
        self.tienda_rect = pygame.Rect(self.tienda_x, self.tienda_y, self.tienda_width, self.tienda_height)
        
        self.panel_x = 920
        self.panel_y = 10
        self.panel_width = 340
        self.panel_height = height - 20
        
        # ===== TIENDA DE MEJORAS =====
        self.mejoras = [
            Mejora("Cursor Mejorado", "+1 click por click", 15, 1.15, "click_power", 1),
            Mejora("Doble Click", "+2 clicks por click", 100, 1.15, "click_power", 2),
            Mejora("Auto Clicker", "1 click automático/seg", 50, 1.2, "auto_click", 1),
            Mejora("Robot Asistente", "5 clicks automáticos/seg", 300, 1.2, "auto_click", 5),
            Mejora("Cursor Dorado", "+5 clicks por click", 500, 1.15, "click_power", 5),
            Mejora("Mega Cursor", "+10 clicks por click", 2000, 1.15, "click_power", 10),
        ]
        
        self.ultimo_auto_click = 0
        self.auto_click_intervalo = 1000  # 1 segundo en ms
        
        # ===== FUENTES =====
        self.font_titulo = pygame.font.Font(pygame.font.get_default_font(), 22)
        self.font_mejora = pygame.font.Font(pygame.font.get_default_font(), 16)
        self.font_pequeno = pygame.font.Font(pygame.font.get_default_font(), 12)
        
        # ===== PANEL DE USUARIO =====
        button_width = 100
        button_height = 40
        
        base_x = self.panel_x + (self.panel_width - button_width) // 2
        base_y = self.panel_y + 50
        
        # Botones de No-Logueado
        self.boton_signin = Boton(base_x, base_y, button_width, button_height, 
                                 "Sign Up", settings.GREEN, settings.WHITE)
        self.boton_login = Boton(base_x, base_y + button_height + 10, button_width, button_height, 
                                "Login", settings.BLUE, settings.WHITE)
        
        # Botones de Logueado
        # --- MODIFICACIÓN: Aumentar el espacio entre botones ---
        self.boton_logout = Boton(base_x, base_y + button_height + 30, button_width, button_height, 
                                "Logout", settings.RED, settings.WHITE) # Gap de 30px
        self.boton_guardar = Boton(base_x, base_y, button_width, button_height, 
                                "Guardar", settings.BLUE, settings.WHITE)
        
        # Estado de autenticación
        self.usuario_logueado = False
        self.nombre_usuario = ""
        
        # Formularios
        self.formulario_registro = FormularioRegistro(self.width, self.height)
        self.formulario_login = FormularioLogin(self.width, self.height)
        
        # Notificación de guardado
        self.notificacion_guardado_tiempo = 0
        
    def handle_event(self, event, cookies=0):
        # Manejar formularios
        if self.formulario_registro.activo:
            resultado = self.formulario_registro.handle_event(event)
            if resultado:
                if isinstance(resultado, tuple) and resultado[0] == "usuario_registrado":
                    return ("usuario_registrado", resultado[1])
                elif resultado == "cancelar":
                    return None
            return None 
            
        if self.formulario_login.activo:
            resultado = self.formulario_login.handle_event(event)
            if resultado:
                if isinstance(resultado, tuple) and resultado[0] == "intento_login":
                    return ("intento_login", resultado[1])
                elif resultado == "cancelar":
                    return None
            return None
        
        # Manejar tienda
        resultado_tienda = self.handle_tienda_event(event, cookies)
        if resultado_tienda:
            return resultado_tienda
        
        # Manejar botones del panel de usuario
        if self.usuario_logueado:
            if self.boton_guardar.handle_event(event):
                return "guardar_juego"
            if self.boton_logout.handle_event(event):
                return "logout"
        else:
            if self.boton_signin.handle_event(event):
                print("Abriendo ventana de registro...")
                self.formulario_registro.mostrar()
                return "signin"
            if self.boton_login.handle_event(event):
                print("Abriendo ventana de login...")
                self.formulario_login.mostrar()
                return "login"
        
        return None
    
    def login_usuario(self, nombre_usuario):
        """Función para loguear un usuario"""
        self.usuario_logueado = True
        self.nombre_usuario = nombre_usuario
        self.formulario_login.ocultar()
        print(f"Usuario {nombre_usuario} logueado exitosamente")
        
    def logout_usuario(self):
        """Función para desloguear un usuario"""
        self.usuario_logueado = False
        self.nombre_usuario = ""
        
        self.formulario_login.ocultar()
        self.formulario_registro.ocultar()
        
        print("Usuario deslogueado")
        
    def update(self):
        """Actualizar componentes que necesiten actualización por tiempo"""
        # --- MODIFICACIÓN: Lógica del temporizador ---
        # Mostrar la notificación de "¡Guardado!" por 2 segundos (120 frames)
        if self.notificacion_guardado_tiempo > 0:
            self.notificacion_guardado_tiempo -= 1
            
        # Llamar a update_tienda y devolver sus auto-clicks
        return self.update_tienda() 
        
    def draw(self, surface, cookies=0):
        """Dibujar tienda y panel de usuario"""
        self.draw_tienda(surface, cookies)
        self._draw_panel_usuario(surface)
        
        self.formulario_registro.draw(surface)
        self.formulario_login.draw(surface)
    
    def _draw_panel_usuario(self, surface):
        """Dibujar el panel de usuario"""
        panel_rect = pygame.Rect(self.panel_x, self.panel_y, self.panel_width, self.panel_height)
        pygame.draw.rect(surface, settings.PANEL_BROWN, panel_rect)
        pygame.draw.rect(surface, settings.GOLDEN, panel_rect, 3)
        
        titulo = self.font_titulo.render("USUARIO", True, settings.TEXT_CREAM)
        titulo_rect = titulo.get_rect(centerx=panel_rect.centerx, y=self.panel_y + 15)
        surface.blit(titulo, titulo_rect)
        
        if not self.usuario_logueado and not self.formulario_registro.activo and not self.formulario_login.activo:
            self.boton_signin.draw(surface)
            self.boton_login.draw(surface)
        elif self.usuario_logueado and not self.formulario_registro.activo and not self.formulario_login.activo:
            
            self.boton_guardar.draw(surface)

            # Mostrar "¡Guardado!" si está activo
            if self.notificacion_guardado_tiempo > 0:
                guardado_text = self.font_mejora.render("¡Guardado!", True, settings.GREEN)
                guardado_rect = guardado_text.get_rect(centerx=self.boton_guardar.rect.centerx,
                                                      y=self.boton_guardar.rect.bottom + 5)
                surface.blit(guardado_text, guardado_rect)

            self.boton_logout.draw(surface)
            
            # Mostrar información del usuario
            welcome_text = self.font_mejora.render(f"Bienvenido!", True, settings.TEXT_CREAM)
            user_text = self.font_mejora.render(f"{self.nombre_usuario}", True, settings.GOLDEN)
            
            surface.blit(welcome_text, (self.panel_x + 20, self.boton_logout.rect.bottom + 30))
            surface.blit(user_text, (self.panel_x + 20, self.boton_logout.rect.bottom + 50))
    
    def mostrar_notificacion_guardado(self):
        """Activa el temporizador para el mensaje "¡Guardado!"""
        # 120 frames = 2 segundos a 60 FPS
        self.notificacion_guardado_tiempo = 120 

    # ===== MÉTODOS DE LA TIENDA DE MEJORAS =====
    
    def update_tienda(self):
        """Actualizar auto-clickers de la tienda (asume 60 FPS)"""
        self.ultimo_auto_click += 16
        auto_clicks = 0
        
        if self.ultimo_auto_click >= self.auto_click_intervalo:
            total_auto_power = 0
            for mejora in self.mejoras:
                if mejora.efecto_tipo == "auto_click":
                    total_auto_power += mejora.get_efecto_total()
            
            if total_auto_power > 0:
                auto_clicks = total_auto_power
                self.ultimo_auto_click = 0
        
        return auto_clicks
    
    def click_power(self):
        """Obtener el poder total de click"""
        base_power = 1
        bonus_power = 0
        for mejora in self.mejoras:
            if mejora.efecto_tipo == "click_power":
                bonus_power += mejora.get_efecto_total()
        
        return base_power + bonus_power
    
    def auto_click_rate(self):
        """Obtener la tasa de auto-clicks por segundo"""
        auto_click_total = 0
        for mejora in self.mejoras:
            if mejora.efecto_tipo == "auto_click":
                auto_click_total += mejora.get_efecto_total()
        return auto_click_total
    
    def handle_tienda_event(self, event, cookies):
        """Manejar eventos específicos de la tienda (sin scroll)"""
        if event.type == pygame.MOUSEBUTTONDOWN and self.tienda_rect.collidepoint(event.pos):
            mouse_x, mouse_y = event.pos
            relative_y = mouse_y - self.tienda_y - 100
            mejora_index = int(relative_y // 80)
            if 0 <= mejora_index < len(self.mejoras):
                mejora = self.mejoras[mejora_index]
                precio = mejora.get_precio_actual()
                if cookies >= precio:
                    mejora.nivel += 1
                    print(f"¡Comprada mejora: {mejora.nombre} (Nivel {mejora.nivel}) por {precio} cookies!")
                    return ("compra_mejora", {"mejora": mejora.nombre, "precio": precio, "nivel": mejora.nivel})
                else:
                    print(f"No tienes suficientes cookies para {mejora.nombre} (necesitas {precio}, tienes {cookies})")
        return None
    
    def draw_tienda(self, surface, cookies):
        """Dibujar la tienda de mejoras (sin scroll)"""
        pygame.draw.rect(surface, settings.PANEL_BROWN, self.tienda_rect)
        pygame.draw.rect(surface, settings.GOLDEN, self.tienda_rect, 3)
        
        titulo = self.font_titulo.render("TIENDA", True, settings.TEXT_CREAM)
        titulo_rect = titulo.get_rect(centerx=self.tienda_rect.centerx, y=self.tienda_y + 15)
        surface.blit(titulo, titulo_rect)
        
        cookies_text = self.font_mejora.render(f"Cookies: {cookies:,}", True, settings.GOLDEN)
        surface.blit(cookies_text, (self.tienda_x + 15, self.tienda_y + 50))
        
        click_power = self.click_power()
        auto_rate = self.auto_click_rate()
        stats_text = self.font_pequeno.render(f"{click_power}/click | {auto_rate}/seg", True, settings.ACCENT_GOLD)
        surface.blit(stats_text, (self.tienda_x + 15, self.tienda_y + 75))
        
        y_offset = 0
        area_altura = self.tienda_height - 120
        max_items = min(len(self.mejoras), area_altura // 80)
        for i in range(max_items):
            mejora = self.mejoras[i]
            self._draw_mejora(surface, mejora, self.tienda_x + 20, self.tienda_y + 100 + y_offset, cookies)
            y_offset += 80
    
    def _draw_mejora(self, surface, mejora, x, y, cookies):
        """Dibujar una mejora individual"""
        precio = mejora.get_precio_actual()
        puede_comprar = cookies >= precio
        
        if puede_comprar:
            color_fondo = settings.LIGHT_BROWN
            borde_color = settings.GOLDEN
            borde_width = 3
            nombre_color = settings.TEXT_CREAM
            precio_color = settings.GOLDEN
        else:
            color_fondo = settings.DARK_BROWN
            borde_color = settings.GRAY
            borde_width = 1
            nombre_color = settings.GRAY
            precio_color = settings.RED
        
        mejora_rect = pygame.Rect(x, y, self.tienda_width - 50, 75)
        pygame.draw.rect(surface, color_fondo, mejora_rect)
        pygame.draw.rect(surface, borde_color, mejora_rect, borde_width)
        
        if puede_comprar:
            highlight_rect = pygame.Rect(x + 2, y + 2, self.tienda_width - 54, 3)
            pygame.draw.rect(surface, settings.GOLDEN, highlight_rect)
        
        nombre_text = self.font_mejora.render(f"{mejora.nombre} (Nv.{mejora.nivel})", True, nombre_color)
        surface.blit(nombre_text, (x + 40, y + 8))
        
        desc_text = self.font_pequeno.render(mejora.descripcion, True, settings.CREAM)
        surface.blit(desc_text, (x + 40, y + 28))
        
        precio_text = self.font_pequeno.render(f" {precio:,} cookies", True, precio_color)
        surface.blit(precio_text, (x + 40, y + 48))
        
        if mejora.nivel > 0:
            efecto_total = mejora.get_efecto_total()
            efecto_text = self.font_pequeno.render(f"Efecto: +{efecto_total}", True, settings.ACCENT_GOLD)
            surface.blit(efecto_text, (x + 40, y + 60))
        
        if puede_comprar:
            click_hint = self.font_pequeno.render("[ CLICK PARA COMPRAR ]", True, settings.GOLDEN)
            text_rect = click_hint.get_rect(right=mejora_rect.right - 10, bottom=mejora_rect.bottom - 5)
            surface.blit(click_hint, text_rect)
    
    def get_mejoras_data(self):
        """Obtener datos de mejoras para guardar en JSON"""
        resultados = []
        for mejora in self.mejoras:
            resultados.append(mejora.to_dict())
        return resultados
    
    def load_mejoras_data(self, data):
        """Cargar datos de mejoras desde JSON"""
        if not data:
            return
        for mejora_data in data:
            nombre = mejora_data["nombre"]
            for mejora in self.mejoras:
                if mejora.nombre == nombre:
                    mejora.from_dict(mejora_data)

    # Wrappers para mantener compatibilidad con core
    def get_click_power(self):
        return self.click_power()

    def get_auto_click_rate(self):
        return self.auto_click_rate()