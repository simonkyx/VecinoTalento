import os
import psycopg2 
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash


# =========================================================
# 1. FLASK APP Y CONFIGURACIÓN DE SEGURIDAD
# =========================================================

app = Flask(__name__)
# Es crucial tener una clave secreta fuerte para la seguridad de la sesión
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CLAVE_DE_FALLO_GENERADA_POR_CODIGO")


# =========================================================
# 2. CONFIGURACIÓN DE CONEXIÓN A POSTGRESQL (LEYENDO DE RENDER)
# =========================================================

def conectar_db():
    try:
        # Render expone la URL de la base de datos interna en esta variable
        # Esto reemplaza todas las variables de Oracle (USER, PASS, DSN)
        DATABASE_URL = os.environ.get("DATABASE_URL")
        
        if not DATABASE_URL:
            # En un entorno local, podrías poner una URL aquí para pruebas
            print("Error: La variable DATABASE_URL no está configurada en Render.")
            return None
        
        # Conexión directa usando la URL de Render
        conn = psycopg2.connect(DATABASE_URL)
        return conn
        
    except psycopg2.Error as e:
        # Esto atrapa los errores de conexión de Postgres
        print(f"Error al conectar a PostgreSQL: {e}") 
        return None


def hash_password(password):
    """Genera el hash SHA256 de la contraseña."""
    return hashlib.sha256(password.encode()).hexdigest()


# =========================================================
# 3. FUNCIONES DE BASE DE DATOS (ADAPTADAS A POSTGRES)
# =========================================================

# --- LOGIN ---
def ejecutar_login_db(email, password):
    conn = conectar_db()
    if not conn:
        return None

    try:
        cursor = conn.cursor()
        hashed = hash_password(password)

        # Usando %s como placeholder para PostgreSQL
        sql = """
        SELECT ID_VECINO, NOMBRE, EMAIL, ESTADO_APROBACION, ROL 
        FROM VECINOS 
        WHERE EMAIL = %s AND PASSWORD_HASH = %s
        """
        cursor.execute(sql, (email, hashed))
        data = cursor.fetchone()

        if data:
            id_vecino, nombre, email_db, estado, rol_db = data

            rol = rol_db if rol_db in ["admin", "vecino"] else "vecino"

            return {
                "id": id_vecino,
                "nombre": nombre,
                "email": email_db,
                "estado": estado,
                "rol": rol
            }

    except Exception as e:
        print("ERROR LOGIN:", e)

    finally:
        if conn:
            conn.close()

    return None


# --- REGISTRO ---
def ejecutar_registro_db(nombre, email, telefono, password):
    conn = conectar_db()
    if not conn:
        return False, "Error de conexión."

    try:
        cursor = conn.cursor()
        hashed = hash_password(password)

        # Verificar si el email ya existe
        cursor.execute("SELECT COUNT(*) FROM VECINOS WHERE EMAIL = %s", (email,))
        if cursor.fetchone()[0] > 0:
            return False, "El email ya está registrado."

        # CAMBIO CRÍTICO: Usamos DEFAULT en lugar de VECINOS_SEQ.NEXTVAL de Oracle
        sql = """
        INSERT INTO VECINOS (ID_VECINO, NOMBRE, EMAIL, TELEFONO, PASSWORD_HASH, ROL, ESTADO_APROBACION)
        VALUES (DEFAULT, %s, %s, %s, %s, 'vecino', 'pendiente')
        """

        cursor.execute(sql, (nombre, email, telefono, hashed))
        conn.commit()
        return True, "Registro exitoso. Tu cuenta está pendiente de aprobación."

    except psycopg2.Error as e:
        # Manejo más específico de errores de BD (ej. duplicados)
        if "unique constraint" in str(e):
              return False, "Error: El email ya existe (Restricción única violada)."
        return False, f"Error de BD: {e}"

    except Exception as e:
        conn.rollback()
        return False, f"Error: {e}"

    finally:
        if conn:
            conn.close()


# --- ADMIN: OBTENER VECINOS ---
def obtener_todos_los_vecinos():
    conn = conectar_db()
    if not conn:
        return [], []

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ID_VECINO, NOMBRE, EMAIL, ESTADO_APROBACION, TELEFONO
            FROM VECINOS
            WHERE LOWER(ROL) != 'admin'
            ORDER BY 
                CASE ESTADO_APROBACION 
                    WHEN 'pendiente' THEN 1 
                    ELSE 2 
                END
        """)
        datos = cursor.fetchall()
        columnas = [col[0] for col in cursor.description]
        return columnas, datos

    except Exception as e:
        print("ERROR OBTENIENDO VECINOS:", e) 
        return [], []

    finally:
        if conn:
            conn.close()


def actualizar_estado_vecino(id_vecino, estado):
    conn = conectar_db()
    if not conn:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE VECINOS SET ESTADO_APROBACION = %s WHERE ID_VECINO = %s", (estado, id_vecino))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("ERROR actualizar_estado_vecino:", e)
        conn.rollback()
        return False
    finally:
        if conn:
            conn.close()


def eliminar_vecino_db(id_vecino):
    conn = conectar_db()
    if not conn:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM VECINOS WHERE ID_VECINO = %s", (id_vecino,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("ERROR eliminar_vecino_db:", e)
        conn.rollback()
        return False
    finally:
        if conn:
            conn.close()


# --- PUBLICACIONES ---
def ejecutar_publicacion_db(tipo, id_vecino, datos):
    conn = conectar_db()
    if not conn:
        return False, "Error de conexión."

    try:
        cursor = conn.cursor()

        # CAMBIO CRÍTICO: Usamos DEFAULT en lugar de las secuencias de Oracle
        if tipo == "oferta":
            sql = """
            INSERT INTO OFERTAS_DE_SERVICIO
            (ID_OFERTA, ID_VECINO, PROFESION_U_OFICIO, DESCRIPCION_DETALLADA, COSTO_ESTIMADO, TELEFONO_CONTACTO)
            VALUES (DEFAULT, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                id_vecino,
                datos.get("profesion"),
                datos.get("descripcion"),
                datos.get("costo", "N/A"),
                datos.get("telefono")
            ))

        elif tipo == "emprendimiento":
            sql = """
                INSERT INTO EMPRENDIMIENTOS 
                (ID_EMPRENDIMIENTO, ID_VECINO, NOMBRE_EMPRENDIMIENTO, TIPO_PRODUCTO, DESCRIPCION, CONTACTO_EMPRENDIMIENTO) 
                VALUES (DEFAULT, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(sql, (
                id_vecino,
                datos.get("nombre"),
                datos.get("tipo"),
                datos.get("descripcion"),
                datos.get("contacto")
            ))

        elif tipo == "aviso":
            sql = """
            INSERT INTO AVISOS_COMUNITARIOS
            (ID_AVISO, ID_VECINO, TIPO_AVISO, TITULO, CONTENIDO, TELEFONO_AVISO)
            VALUES (DEFAULT, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                id_vecino,
                datos.get("tipo_aviso"),
                datos.get("titulo"),
                datos.get("contenido"),
                datos.get("telefono")
            ))
        else:
            return False, "Tipo de publicación no válido."

        conn.commit()
        return True, "Publicación creada exitosamente."

    except Exception as e:
        conn.rollback()
        print(f"ERROR AL INTENTAR PUBLICAR: {e}")  
        return False, f"Error al publicar: {e}"

    finally:
        if conn:
            conn.close()


# --- PUBLICACIONES (Actualizada para incluir ID en Admin) ---
def obtener_publicaciones(tipo, busqueda=""):
    conn = conectar_db()
    if not conn:
        return [], []

    try:
        cursor = conn.cursor()
        busqueda_param = f"%{busqueda.lower()}%"
        
        # PostgreSQL usa ILIKE para búsquedas insensibles a mayúsculas
        if tipo == "oferta":
            sql = """
            SELECT T1.ID_OFERTA, T1.PROFESION_U_OFICIO, T1.DESCRIPCION_DETALLADA, T1.COSTO_ESTIMADO, T1.TELEFONO_CONTACTO, T2.NOMBRE
            FROM OFERTAS_DE_SERVICIO T1
            JOIN VECINOS T2 ON T1.ID_VECINO = T2.ID_VECINO
              AND (T1.PROFESION_U_OFICIO ILIKE %s OR T1.DESCRIPCION_DETALLADA ILIKE %s)
            ORDER BY T1.FECHA_PUBLICACION DESC
            """
            cursor.execute(sql, (busqueda_param, busqueda_param))

        elif tipo == "emprendimiento":
            sql = """
            SELECT T1.ID_EMPRENDIMIENTO, T1.NOMBRE_EMPRENDIMIENTO, T1.TIPO_PRODUCTO, T1.DESCRIPCION, T1.CONTACTO_EMPRENDIMIENTO, T2.NOMBRE
            FROM EMPRENDIMIENTOS T1
            JOIN VECINOS T2 ON T1.ID_VECINO = T2.ID_VECINO
            ORDER BY T1.FECHA_PUBLICACION DESC
            """
            cursor.execute(sql)

        elif tipo == "aviso":
            sql = """
            SELECT T1.ID_AVISO, T1.TIPO_AVISO, T1.TITULO, T1.CONTENIDO, T1.TELEFONO_AVISO, T2.NOMBRE
            FROM AVISOS_COMUNITARIOS T1
            JOIN VECINOS T2 ON T1.ID_VECINO = T2.ID_VECINO
            ORDER BY T1.FECHA_PUBLICACION DESC
            """
            cursor.execute(sql)
            
        else:
            return [], []

        datos = cursor.fetchall()
        columnas = [col[0] for col in cursor.description]
        return columnas, datos

    except Exception as e:
        print("ERROR al obtener publicaciones:", e)
        return [], []

    finally:
        if conn:
            conn.close()


# --- ADMIN: ELIMINAR PUBLICACIÓN ---
def eliminar_publicacion_db(tipo, id_publicacion):
    conn = conectar_db()
    if not conn:
        return False, "Error de conexión."
    
    tablas = {
        "oferta": ("OFERTAS_DE_SERVICIO", "ID_OFERTA"),
        "emprendimiento": ("EMPRENDIMIENTOS", "ID_EMPRENDIMIENTO"),
        "aviso": ("AVISOS_COMUNITARIOS", "ID_AVISO")
    }

    if tipo not in tablas:
        return False, "Tipo de publicación no válido."

    tabla, columna_id = tablas[tipo]
    
    try:
        cursor = conn.cursor()
        
        # Sentencia SQL dinámica para eliminar la fila específica
        sql = f"DELETE FROM {tabla} WHERE {columna_id} = %s"
        
        cursor.execute(sql, (id_publicacion,))
        conn.commit()
        
        if cursor.rowcount > 0:
            return True, f"{tabla} con ID {id_publicacion} eliminada correctamente."
        else:
            return False, "La publicación no existe o no se pudo eliminar."
            
    except Exception as e:
        conn.rollback()
        print(f"ERROR AL ELIMINAR PUBLICACIÓN: {e}")  
        return False, f"Error de BD: {e}"
        
    finally:
        if conn:
            conn.close()


# =========================================================
# 4. FLASK ROUTES 
# =========================================================

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    
    user = session["user"]
    
    if user["rol"] == "admin":
        return redirect(url_for("admin_menu"))
        
    if user["estado"] != "aprobado":
        flash("Tu cuenta aún está pendiente de aprobación.", "warning")
        
    return redirect(url_for("user_menu"))


# --- LOGIN ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        is_admin = request.form.get("is_admin") == "on"

        if is_admin:
            email = "admin@vecinotalento.cl" # Uso del email del administrador

        user = ejecutar_login_db(email, password)

        if user:
            # Si no es admin y no está aprobado, no puede pasar
            if user["rol"] != "admin" and user["estado"] != "aprobado":
                flash("Tu cuenta aún está pendiente de aprobación por el administrador.", "warning")
                return redirect(url_for("login"))
            
            session["user"] = user
            return redirect(url_for("admin_menu" if user["rol"] == "admin" else "user_menu"))

        flash("Credenciales inválidas o cuenta no aprobada.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))


# --- REGISTRO ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form["nombre"]
        email = request.form["email"]
        telefono = request.form["telefono"]
        password = request.form["password"]

        ok, msg = ejecutar_registro_db(nombre, email, telefono, password)

        flash(msg, "success" if ok else "error")
        if ok:
            return redirect(url_for("login"))

    return render_template("register.html")


# --- MENÚ VECINO ---
@app.route("/menu_vecino")
def user_menu():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if session["user"]["rol"] == "admin":
        return redirect(url_for("admin_menu"))
        
    return render_template("user_menu.html", user=session["user"])


# --- VER PUBLICACIONES ---
@app.route("/view_content/<tipo>", methods=["GET", "POST"])
def view_content(tipo):
    if "user" not in session:
        return redirect(url_for("login"))

    busqueda = request.form.get("busqueda", "") if tipo == "oferta" and request.method == "POST" else ""

    # La función obtener_publicaciones ahora devuelve el ID en la primera columna
    columnas, resultados = obtener_publicaciones(tipo, busqueda)
    
    # Prepara las columnas y resultados para la vista de usuario (ocultando el ID)
    if columnas:
        columnas_user = columnas[1:]
        resultados_user = [fila[1:] for fila in resultados]
    else:
        columnas_user = []
        resultados_user = []


    titulos = {
        "oferta": "Ofertas de Servicio",
        "emprendimiento": "Emprendimientos Comunitarios",
        "aviso": "Avisos Comunitarios"
    }

    return render_template(
        "view_content.html",
        tipo=tipo,
        titulo=titulos.get(tipo, "Contenido"),
        columnas=columnas_user,
        resultados=resultados_user
    )


# --- PUBLICAR ---
@app.route("/publish/<tipo>", methods=["GET", "POST"])
def publish(tipo):
    if "user" not in session:
        return redirect(url_for("login"))

    if session["user"]["estado"] != "aprobado":
        flash("Tu cuenta aún no está aprobada. No puedes publicar.", "warning")
        return redirect(url_for("user_menu"))

    campos = {
        "oferta": [
            ("profesion", "Profesión u Oficio"),
            ("descripcion", "Descripción Detallada"),
            ("costo", "Costo Estimado (opcional)"),
            ("telefono", "Teléfono de Contacto")
        ],
        "emprendimiento": [
            ("nombre", "Nombre del Emprendimiento"),
            ("tipo", "Tipo de Producto/Servicio"),
            ("descripcion", "Descripción"),
            ("contacto", "Contacto (Redes Sociales o Email)")
        ],
        "aviso": [
            ("tipo_aviso", "Tipo de Aviso (Ej: Venta, Evento, Perdido)"),
            ("titulo", "Título del Aviso"),
            ("contenido", "Contenido del Aviso"),
            ("telefono", "Teléfono de Contacto")
        ]
    }

    if tipo not in campos:
        flash("Tipo de publicación no válido.", "error")
        return redirect(url_for("user_menu"))

    if request.method == "POST":
        ok, msg = ejecutar_publicacion_db(tipo, session["user"]["id"], request.form)
        flash(msg, "success" if ok else "error")
        if ok:
            return redirect(url_for("user_menu"))

    return render_template("publish.html", tipo=tipo, campos=campos[tipo])


# --- ADMIN ---
@app.route("/admin_menu")
def admin_menu():
    if "user" not in session or session["user"]["rol"] != "admin":
        return redirect(url_for("login"))
    return render_template("admin_menu.html", user=session["user"])


@app.route("/admin/manage_neighbors")
def manage_neighbors():
    if "user" not in session or session["user"]["rol"] != "admin":
        return redirect(url_for("login"))

    columnas, vecinos = obtener_todos_los_vecinos()
    return render_template("manage_neighbors.html", columnas=columnas, vecinos=vecinos)


# Endpoint de acción: update_neighbor
@app.route("/admin/update_neighbor/<int:id_vecino>/<estado>")
def update_neighbor(id_vecino, estado):
    if "user" not in session or session["user"]["rol"] != "admin":
        return redirect(url_for("login"))

    if actualizar_estado_vecino(id_vecino, estado):
        flash(f"Estado del vecino ID {id_vecino} actualizado a '{estado.upper()}'.", "success")
    else:
        flash("Error al actualizar el estado del vecino.", "error")
        
    return redirect(url_for("manage_neighbors"))


# Endpoint de acción: delete_neighbor
@app.route("/admin/delete_neighbor/<int:id_vecino>")
def delete_neighbor(id_vecino):
    if "user" not in session or session["user"]["rol"] != "admin":
        return redirect(url_for("login"))

    if eliminar_vecino_db(id_vecino):
        flash(f"Vecino ID {id_vecino} eliminado correctamente.", "success")
    else:
        flash("Error al eliminar el vecino.", "error")
        
    return redirect(url_for("manage_neighbors"))


# --- ADMIN: GESTIONAR PUBLICACIONES (VER Y PREPARAR ELIMINACIÓN) ---
@app.route("/admin/manage_content/<tipo>")
def manage_content(tipo):
    if "user" not in session or session["user"]["rol"] != "admin":
        return redirect(url_for("login"))

    titulos = {
        "oferta": "Gestión de Ofertas de Servicio",
        "emprendimiento": "Gestión de Emprendimientos",
        "aviso": "Gestión de Avisos Comunitarios"
    }
    
    # La función obtener_publicaciones devuelve el ID en la primera columna
    columnas, resultados = obtener_publicaciones(tipo)
    
    return render_template(
        "manage_content.html",
        tipo=tipo,
        titulo=titulos.get(tipo, "Gestión de Publicaciones"),
        columnas=columnas,
        resultados=resultados
    )


# --- ADMIN: ACCIÓN DE ELIMINACIÓN ---
@app.route("/admin/delete_content_action/<tipo>/<int:id_publicacion>")
def delete_content_action(tipo, id_publicacion):
    if "user" not in session or session["user"]["rol"] != "admin":
        return redirect(url_for("login"))

    ok, msg = eliminar_publicacion_db(tipo, id_publicacion)
    
    flash(msg, "success" if ok else "error")
    
    # Redirigir de vuelta a la página de gestión de contenido
    return redirect(url_for("manage_content", tipo=tipo))


# =========================================================
# EJECUTAR APP
# =========================================================
if __name__ == "__main__":
    app.run(debug=True)
