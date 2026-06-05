"""
Clase principal del juego Cookie Clicker
Maneja el bucle principal, los eventos y el estado del juego.
"""
import pygame
import math
from core import settings
from entities.contador import Contador
from entities.circulo import Circulo
from core.menu import Menu
from core.manejador_datos import ManejadorDatos


class Juego:
    """
    Clase principal que maneja todo el juego Cookie Clicker
    """
    
    def __init__(self, width, height):
        """Inicializar el juego con todas sus componentes"""
        self.width = width
        self.height = height
        
        # Layout: galleta (izq) | tienda (centro) | usuario (der)
        galleta_x = 150
        galleta_y = height//2 - 150
        contador_x = 80  
        contador_y = galleta_y + 250
        
        self.circulo = Circulo(galleta_x, galleta_y)
        self.contador = Contador(contador_x, contador_y)
        self.menu = Menu(width, height)
        
        # Cliente API para el servidor
        self.manejador_datos = ManejadorDatos()
        
        # Estado del usuario
        self.usuario_actual = None
        self.usuario_logueado = False
    
    def update(self):
        """Actualizar la lógica del juego cada fotograma"""
        # Llama a update del menú para manejar la tienda y el temporizador de "¡Guardado!"
        auto_clicks = self.menu.update() 
        
        if auto_clicks > 0:
            self.contador.añadir_cookies(auto_clicks)
        
        self.contador.cookies_por_segundo = self.menu.auto_click_rate()
        self.contador.cookies_por_click = self.menu.click_power()
    
    def draw(self, screen):
        """Dibujar todos los componentes en pantalla"""
        self.circulo.draw(screen)
        self.contador.draw(screen)
        self.menu.draw(screen, self.contador.cookies)
    
    def handle_event(self, event):
        """Manejar todas las entradas del usuario"""
        
        # El menú (UI) tiene prioridad para manejar eventos
        accion_menu = self.menu.handle_event(event, self.contador.cookies)
        
        # Procesar acciones devueltas por el menú
        if isinstance(accion_menu, tuple) and len(accion_menu) == 2:
            tipo_accion, datos = accion_menu
            
            if tipo_accion == "usuario_registrado":
                self._procesar_registro_usuario(datos)
            elif tipo_accion == "intento_login":
                self._procesar_intento_login(datos)
            elif tipo_accion == "compra_mejora":
                self._procesar_compra_mejora(datos)
        
        elif isinstance(accion_menu, str):
            if accion_menu == "logout":
                self._procesar_logout()
            elif accion_menu == "guardar_juego":
                self._guardar_datos_servidor()
                
        # Si los formularios están activos, no permitir click en galleta
        if self.menu.formulario_registro.activo or self.menu.formulario_login.activo:
            return
        
        # Procesar click en galleta
        if event.type != pygame.MOUSEBUTTONDOWN:
            return
        
        coord_x = event.pos[0] - self.circulo.rect.centerx
        coord_y = event.pos[1] - self.circulo.rect.centery
        if math.sqrt(coord_x**2 + coord_y**2) <= 100:
            click_power = self.menu.click_power()
            self.contador.añadir_cookies(click_power)
            self.circulo.on_click(click_power)
    
    def _guardar_datos_servidor(self):
        if self.usuario_logueado and self.usuario_actual:
            print("[Juego] Guardando datos en el servidor...")
            # Prepara UN SOLO diccionario con ambos datos
            datos_completos = {
                "cookies": self.contador.cookies,
                "mejoras": self.menu.get_mejoras_data() 
            }
            
            # Llama a la función de envío con ese diccionario
            respuesta = self.manejador_datos.actualizar(datos_completos) 
            if respuesta:
                print("[Juego] ¡Datos guardados!")
                self.menu.mostrar_notificacion_guardado()
            else:
                print("[Juego] Fallo a la hora de guardar.")
        else:
            print("[Juego] No se puede guardar: Usuario no logueado.")

    def _procesar_registro_usuario(self, datos_usuario):
        """Intenta registrar un nuevo usuario y hace auto-login si tiene éxito."""
        if not datos_usuario:
            self.menu.formulario_registro.mostrar_resultado("Error: Faltan datos (core)", (255, 100, 100))
            return

        print("[Juego] Contactando al servidor para registrar...")
        # Ahora esperamos un diccionario de usuario, no un booleano
        respuesta_registro = self.manejador_datos.registrar_usuario(datos_usuario)
        
        if respuesta_registro:
            print("[Juego] Registro y auto-login exitosos.")
            # Si el registro tuvo éxito, llamamos a _realizar_login directamente
            usuario = respuesta_registro.get("usuario")
            if usuario:
                self._realizar_login(usuario, respuesta_registro)
            else:
                self.menu.formulario_registro.mostrar_resultado("Error: Respuesta inválida", (255, 100, 100))
        else:
            # El registro falló (ej. usuario ya existe)
            self.menu.formulario_registro.mostrar_resultado("Error: Usuario o email ya existen.", (255, 100, 100))
    
    def _procesar_intento_login(self, datos_login):
        """Intenta validar las credenciales de un usuario contra el servidor."""
        if not datos_login:
            self.menu.formulario_login.mostrar_resultado_login(False, "Faltan datos")
            return

        print("[Juego] Contactando al servidor para login...")
        # Esperamos un diccionario de usuario
        respuesta_login = self.manejador_datos.validar_login(datos_login)
        
        if respuesta_login:
            usuario = respuesta_login.get("usuario")
            if usuario:
                self._realizar_login(usuario, respuesta_login)
            else:
                self.menu.formulario_login.mostrar_resultado_login(False, "Error servidor")
        else:
            # El login falló (ej. credenciales inválidas)
            self.menu.formulario_login.mostrar_resultado_login(False, "Credenciales inválidas")

    
    def _procesar_logout(self):
        """Guarda el juego, cierra la sesión y resetea el estado local."""
        if self.usuario_logueado:
            print("[Juego] Procesando logout...")
            
            # Guardar antes de salir
            self._guardar_datos_servidor()
            
            # Desconectar y comprobar el resultado
            exito_servidor = self.manejador_datos.logout(self.usuario_actual)
            
            if not exito_servidor:
                print("[Juego] ADVERTENCIA: No se pudo cerrar la sesión en el servidor.")
                return

            # Resetear estado local (esto se hace SIEMPRE)
            self.usuario_actual = None
            self.usuario_logueado = False
            self.contador.reiniciar()
            for mejora in self.menu.mejoras:
                mejora.nivel = 0
                
            self.menu.logout_usuario()
            print("[Juego] Sesión local cerrada.")
    
    def _realizar_login(self, nombre_usuario, datos_juego):
        """Configura el estado del juego una vez que el login es exitoso."""
        self.usuario_actual = nombre_usuario
        self.usuario_logueado = True
        
        # Ocultar AMBOS formularios
        self.menu.formulario_login.ocultar()
        self.menu.formulario_registro.ocultar()
        
        self.menu.login_usuario(nombre_usuario)
        
        # Cargar datos del servidor
        self.contador.cookies = datos_juego.get("cookies", 0)
        self.menu.load_mejoras_data(datos_juego.get("mejoras", []))
        
        print(f"[Juego] Login exitoso para {nombre_usuario}. Datos cargados.")
    
    def _procesar_compra_mejora(self, datos_compra):
        """Procesa la compra de una mejora localmente."""
        precio = datos_compra.get("precio", 0)
        
        if self.contador.cookies >= precio:
            self.contador.cookies -= precio
        else:
            print("[Juego] ERROR: Intento de compra sin fondos (desincronización)")