import os
import psycopg2 
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash


# =========================================================
# 1. FLASK APP Y CONFIGURACIÓN DE SEGURIDAD
# =========================================================

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CLAVE_DE_FALLO_GENERADA_POR_CODIGO")


# =========================================================
# 2. CONFIGURACIÓN DE CONEXIÓN A POSTGRESQL (LEYENDO DE RENDER)
# =========================================================

def conectar_db():
    try:
        # Render expone la URL de la base de datos interna en esta variable
        DATABASE_URL = os.environ.get("DATABASE_URL")
        
        if not DATABASE_URL:
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

        # ⬅️ CAMBIO: Nombre de tabla a minúsculas
        sql = """
        SELECT id_vecino, nombre, email, estado_aprobacion, rol 
        FROM vecinos 
        WHERE email = %s AND password_hash = %s
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

        # ⬅️ CAMBIO: Nombre de tabla a minúsculas
        cursor.execute("SELECT COUNT(*) FROM vecinos WHERE email = %s", (email,))
        if cursor.fetchone()[0] > 0:
            return False, "El email ya está registrado."

        # ⬅️ CAMBIO: Nombre de tabla a minúsculas
        sql = """
        INSERT INTO vecinos (id_vecino, nombre, email, telefono, password_hash, rol, estado_aprobacion)
        VALUES (DEFAULT, %s, %s, %s, %s, 'vecino', 'pendiente')
        """

        cursor.execute(sql, (nombre, email, telefono, hashed))
        conn.commit()
        return True, "Registro exitoso. Tu cuenta está pendiente de aprobación."

    except psycopg2.Error as e:
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
        # ⬅️ CAMBIO: Nombre de tabla a minúsculas
        cursor.execute("""
            SELECT id_vecino, nombre, email, estado_aprobacion, telefono
            FROM vecinos
            WHERE LOWER(rol) != 'admin'
            ORDER BY 
                CASE estado_aprobacion 
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
        # ⬅️ CAMBIO: Nombre de tabla a minúsculas
        cursor = conn.cursor()
        cursor.execute("UPDATE vecinos SET estado_aprobacion = %s WHERE id_vecino = %s", (estado, id_vecino))
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
        # ⬅️ CAMBIO: Nombre de tabla a minúsculas
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vecinos WHERE id_vecino = %s", (id_vecino,))
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

        if tipo == "oferta":
            # ⬅️ CAMBIO: Nombre de tabla a minúsculas
            sql = """
            INSERT INTO ofertas_de_servicio
            (id_oferta, id_vecino, profesion_u_oficio, descripcion_detallada, costo_estimado, telefono_contacto)
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
            # ⬅️ CAMBIO: Nombre de tabla a minúsculas
            sql = """
                INSERT INTO emprendimientos 
                (id_emprendimiento, id_vecino, nombre_emprendimiento, tipo_producto, descripcion, contacto_emprendimiento) 
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
            # ⬅️ CAMBIO: Nombre de tabla a minúsculas
            sql = """
            INSERT INTO avisos_comunitarios
            (id_aviso, id_vecino, tipo_aviso, titulo, contenido, telefono_aviso)
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
        
        if tipo == "oferta":
            # ⬅️ CAMBIO: Nombre de tabla a minúsculas
            sql = """
            SELECT T1.id_oferta, T1.profesion_u_oficio, T1.descripcion_detallada, T1.costo_estimado, T1.telefono_contacto, T2.nombre
            FROM ofertas_de_servicio T1
            JOIN vecinos T2 ON T1.id_vecino = T2.id_vecino
              AND (T1.profesion_u_oficio ILIKE %s OR T1.descripcion_detallada ILIKE %s)
            ORDER BY T1.fecha_publicacion DESC
            """
            cursor.execute(sql, (busqueda_param, busqueda_param))

        elif tipo == "emprendimiento":
            # ⬅️ CAMBIO: Nombre de tabla a minúsculas
            sql = """
            SELECT T1.id_emprendimiento, T1.nombre_emprendimiento, T1.tipo_producto, T1.descripcion, T1.contacto_emprendimiento, T2.nombre
            FROM emprendimientos T1
            JOIN vecinos T2 ON T1.id_vecino = T2.id_vecino
            ORDER BY T1.fecha_publicacion DESC
            """
            cursor.execute(sql)

        elif tipo == "aviso":
            # ⬅️ CAMBIO: Nombre de tabla a minúsculas
            sql = """
            SELECT T1.id_aviso, T1.tipo_aviso, T1.titulo, T1.contenido, T1.telefono_aviso, T2.nombre
            FROM avisos_comunitarios T1
            JOIN vecinos T2 ON T1.id_vecino = T2.id_vecino
            ORDER BY T1.fecha_publicacion DESC
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
    
    # ⬅️ CAMBIO: Nombres de tabla a minúsculas
    tablas = {
        "oferta": ("ofertas_de_servicio", "id_oferta"),
        "emprendimiento": ("emprendimientos", "id_emprendimiento"),
        "aviso": ("avisos_comunitarios", "id_aviso")
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
            email = "admin@vecinotalento.cl"

        user = ejecutar_login_db(email, password)

        if user:
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

    columnas, resultados = obtener_publicaciones(tipo, busqueda)
    
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
    
    return redirect(url_for("manage_content", tipo=tipo))


# =========================================================
# EJECUTAR APP
# =========================================================
if __name__ == "__main__":
    app.run(debug=True)
