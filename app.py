import oracledb
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash


# =========================================================
# 1. CONFIGURACIÓN DE CONEXIÓN A ORACLE
# =========================================================
usuario_db = "SIMON_CALFUCURA"
contrasena_db = "12345"
dsn_completo = "195.26.252.168:1521/XEPDB1" # Asegúrate de que este DSN sea correcto

def conectar_db():
    try:
        return oracledb.connect(
            user=usuario_db,
            password=contrasena_db,
            dsn=dsn_completo
        )
    except oracledb.DatabaseError as e:
        print(f"Error al conectar a Oracle: {e}")
        return None


def hash_password(password):
    """Genera el hash SHA256 de la contraseña."""
    return hashlib.sha256(password.encode()).hexdigest()


# =========================================================
# 2. FUNCIONES DE BASE DE DATOS (CORRECCIONES INTEGRADAS)
# =========================================================

# --- LOGIN ---
def ejecutar_login_db(email, password):
    conn = conectar_db()
    if not conn:
        return None

    try:
        cursor = conn.cursor()
        hashed = hash_password(password)

        sql = """
        SELECT ID_VECINO, NOMBRE, EMAIL, ESTADO_APROBACION, ROL 
        FROM VECINOS 
        WHERE EMAIL = :email AND PASSWORD_HASH = :password
        """
        cursor.execute(sql, email=email, password=hashed)
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

        cursor.execute("SELECT COUNT(*) FROM VECINOS WHERE EMAIL = :email", email=email)
        if cursor.fetchone()[0] > 0:
            return False, "El email ya está registrado."

        sql = """
        INSERT INTO VECINOS (ID_VECINO, NOMBRE, EMAIL, TELEFONO, PASSWORD_HASH, ROL, ESTADO_APROBACION)
        VALUES (VECINOS_SEQ.NEXTVAL, :nombre, :email, :telefono, :contrasena, 'vecino', 'pendiente')
        """

        cursor.execute(sql,
            nombre=nombre,
            email=email,
            telefono=telefono,
            contrasena=hashed  
        )
        conn.commit()
        return True, "Registro exitoso. Tu cuenta está pendiente de aprobación."

    except oracledb.DatabaseError as e:
        if "ORA-00001" in str(e):
             return False, "Error: El email o ID ya existe (Restricción única violada)."
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
        cursor.execute("UPDATE VECINOS SET ESTADO_APROBACION = :estado WHERE ID_VECINO = :id", estado=estado, id=id_vecino)
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
        cursor.execute("DELETE FROM VECINOS WHERE ID_VECINO = :id", id=id_vecino)
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print("ERROR eliminar_vecino_db:", e)
        conn.rollback()
        return False
    finally:
        if conn:
            conn.close()


# --- PUBLICACIONES (CON TODAS LAS CORRECCIONES INTEGRADAS) ---
def ejecutar_publicacion_db(tipo, id_vecino, datos):
    conn = conectar_db()
    if not conn:
        return False, "Error de conexión."

    try:
        cursor = conn.cursor()

        if tipo == "oferta":
            # 1. Sin ESTADO_APROBACION. 2. Bind variables seguros (:v_desc, etc.)
            sql = """
            INSERT INTO OFERTAS_DE_SERVICIO
            (ID_OFERTA, ID_VECINO, PROFESION_U_OFICIO, DESCRIPCION_DETALLADA, COSTO_ESTIMADO, TELEFONO_CONTACTO)
            VALUES (OFERTAS_SERVICIOS_SEQ.NEXTVAL, :v_idv, :v_prof, :v_desc, :v_costo, :v_tel)
            """
            cursor.execute(sql,
                v_idv=id_vecino,
                v_prof=datos.get("profesion"),
                v_desc=datos.get("descripcion"),
                v_costo=datos.get("costo", "N/A"),
                v_tel=datos.get("telefono")
            )

        elif tipo == "emprendimiento":
            # 1. Sin ESTADO_APROBACION. 2. Columna "DESCRIPCION" entre comillas. 3. Bind variables seguros.
            sql = (
                "INSERT INTO EMPRENDIMIENTOS "
                "(ID_EMPRENDIMIENTO, ID_VECINO, NOMBRE_EMPRENDIMIENTO, TIPO_PRODUCTO, \"DESCRIPCION\", CONTACTO_EMPRENDIMIENTO) "
                "VALUES (EMPRENDIMIENTOS_SEQ.NEXTVAL, :v_id_vecino, :v_nombre_emp, :v_tipo_prod, :v_desc_emp, :v_contacto_emp)"
            )
            
            cursor.execute(sql,
                v_id_vecino=id_vecino,
                v_nombre_emp=datos.get("nombre"),
                v_tipo_prod=datos.get("tipo"),
                v_desc_emp=datos.get("descripcion"),
                v_contacto_emp=datos.get("contacto")
            )

        elif tipo == "aviso":
            # 1. Sin ESTADO_APROBACION. 2. Columna "CONTENIDO" entre comillas. 3. Bind variables seguros.
            sql = """
            INSERT INTO AVISOS_COMUNITARIOS
            (ID_AVISO, ID_VECINO, TIPO_AVISO, TITULO, "CONTENIDO", TELEFONO_AVISO)
            VALUES (AVISOS_COMUNITARIOS_SEQ.NEXTVAL, :v_idv, :v_tipoa, :v_tit, :v_cont, :v_tel)
            """
            cursor.execute(sql,
                v_idv=id_vecino,
                v_tipoa=datos.get("tipo_aviso"),
                v_tit=datos.get("titulo"),
                v_cont=datos.get("contenido"),
                v_tel=datos.get("telefono")
            )
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


# --- PUBLICACIONES (Actualizada para incluir ID en Admin y sin ESTADO_APROBACION en el WHERE) ---
def obtener_publicaciones(tipo, busqueda=""):
    conn = conectar_db()
    if not conn:
        return [], []

    try:
        cursor = conn.cursor()
        busqueda_param = f"%{busqueda.lower()}%"
        
        # Se añade el ID de la publicación a todas las consultas SELECT
        if tipo == "oferta":
            sql = """
            SELECT T1.ID_OFERTA, T1.PROFESION_U_OFICIO, T1.DESCRIPCION_DETALLADA, T1.COSTO_ESTIMADO, T1.TELEFONO_CONTACTO, T2.NOMBRE
            FROM OFERTAS_DE_SERVICIO T1
            JOIN VECINOS T2 ON T1.ID_VECINO = T2.ID_VECINO
              AND (LOWER(T1.PROFESION_U_OFICIO) LIKE :b OR LOWER(T1.DESCRIPCION_DETALLADA) LIKE :b)
            ORDER BY T1.FECHA_PUBLICACION DESC
            """
            cursor.execute(sql, b=busqueda_param)

        elif tipo == "emprendimiento":
            sql = """
            SELECT T1.ID_EMPRENDIMIENTO, T1.NOMBRE_EMPRENDIMIENTO, T1.TIPO_PRODUCTO, T1."DESCRIPCION", T1.CONTACTO_EMPRENDIMIENTO, T2.NOMBRE
            FROM EMPRENDIMIENTOS T1
            JOIN VECINOS T2 ON T1.ID_VECINO = T2.ID_VECINO
            ORDER BY T1.FECHA_PUBLICACION DESC
            """
            cursor.execute(sql)

        elif tipo == "aviso":
            sql = """
            SELECT T1.ID_AVISO, T1.TIPO_AVISO, T1.TITULO, T1."CONTENIDO", T1.TELEFONO_AVISO, T2.NOMBRE
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
        sql = f"DELETE FROM {tabla} WHERE {columna_id} = :id"
        
        cursor.execute(sql, id=id_publicacion)
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
# 3. FLASK ROUTES
# =========================================================

app = Flask(__name__)
app.secret_key = "clave_super_secreta_a_cambiar"


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

    # Se llama a obtener_publicaciones, pero solo se muestran las columnas a partir del índice 1 (para ocultar el ID)
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
    
    # La función obtener_publicaciones ahora devuelve el ID en la primera columna
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