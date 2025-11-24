from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
from sqlalchemy import select, text  # Necesario para consultas modernas y SQL puro
from flask_bcrypt import Bcrypt  # Necesario para hashear contraseñas
from flask_cors import CORS
from datetime import datetime

# ==============================================
# 1. CARGA DE VARIABLES DE ENTORNO
load_dotenv()
# ==============================================

app = Flask(__name__)
CORS(app)

# --- 2. CONFIGURACIÓN DE CONEXIÓN ---
DB_USER = os.environ.get("MYSQLUSER")
DB_PASS = os.environ.get("MYSQLPASSWORD")
DB_HOST = os.environ.get("MYSQLHOST")
DB_PORT = os.environ.get("MYSQLPORT")
DB_NAME = os.environ.get("MYSQLDATABASE")

# Construye la URI de conexión
app.config['SQLALCHEMY_DATABASE_URI'] = \
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Inicializa Bcrypt


# --- 3. DEFINICIÓN DE MODELOS ---

class User(db.Model):
    __tablename__ = 'usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nom_1 = db.Column(db.String(50), nullable=False)
    nom_2 = db.Column(db.String(50))
    app_1 = db.Column(db.String(50), nullable=False)
    app_2 = db.Column(db.String(50))
    correo = db.Column(db.String(120), unique=True, nullable=False)
    # Columna que coincide con el nombre de la DB (contrasena, sin tilde)
    contrasena = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        """Método para serializar el objeto a diccionario/JSON"""
        return {
            "id": self.id_usuario,
            "nombre1": self.nom_1,
            "nombre2": self.nom_2,
            "apellido1": self.app_1,
            "apellido2": self.app_2,
            "correo": self.correo,
        }


class Subasta(db.Model):
    __tablename__ = 'subasta'

    # CLAVE: Ya no necesitamos autoincrement=True aquí si la DB ya fue corregida
    id_subasta = db.Column(db.Integer, primary_key=True)
    # Foreign Key: Conexión con la tabla 'usuario', columna 'id_usuario'
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)

    fecha_ini = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_fin = db.Column(db.DateTime)
    descripcion = db.Column(db.Text)
    precio_base = db.Column(db.Numeric(10, 2))

    creador = db.relationship('User', backref=db.backref('mis_subastas', lazy=True))

    def to_dict(self):
        return {
            "id_subasta": self.id_subasta,
            "id_usuario": self.id_usuario,
            "fecha_ini": self.fecha_ini.isoformat() if self.fecha_ini else None,
            "fecha_fin": self.fecha_fin.isoformat() if self.fecha_fin else None,
            "descripcion": self.descripcion,
            "precio_base": str(self.precio_base)
        }


# --- MODELO PUJA ---
class Puja(db.Model):
    __tablename__ = 'puja'

    id_puja = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    id_subasta = db.Column(db.Integer, db.ForeignKey('subasta.id_subasta'), nullable=False)

    puja = db.Column(db.Numeric(10, 2), nullable=False)
    fecha_puja = db.Column(db.DateTime, default=datetime.utcnow)

    usuario_pujador = db.relationship('User', backref=db.backref('mis_pujas', lazy=True))
    subasta_objetivo = db.relationship('Subasta', backref=db.backref('pujas_recibidas', lazy=True))

    def to_dict(self):
        return {
            "id_puja": self.id_puja,
            "id_usuario": self.id_usuario,
            "id_subasta": self.id_subasta,
            "monto": str(self.puja),
            "fecha": self.fecha_puja.isoformat() if self.fecha_puja else None
        }


# --- MODELO IMAGEN (Simplificado) ---
class Imagen(db.Model):
    __tablename__ = 'imagen'
    id_imagen = db.Column(db.Integer, primary_key=True)
    id_subasta = db.Column(db.Integer, db.ForeignKey('subasta.id_subasta'), nullable=False)
    datos_imagen = db.Column(db.LargeBinary)
    subasta = db.relationship('Subasta', backref=db.backref('imagenes', lazy=True))

    def to_dict(self):
        return {
            "id_imagen": self.id_imagen,
            "id_subasta": self.id_subasta,
            "url_o_datos": "Datos binarios (no mostrados en API)"
        }


# ======================================================
# RUTAS DE LA API (CRUD Y AUTENTICACIÓN)
# ======================================================

@app.route('/')
def root():
    return jsonify("Hola jotos")


# RUTA POST: INICIAR SESIÓN
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or 'correo' not in data or 'contraseña' not in data:
        return jsonify({"error": "Faltan campos (correo, contraseña)"}), 400

    user_correo = data['correo']
    user_password = data['contraseña']

    try:
        stmt = select(User).filter_by(correo=user_correo)
        user = db.session.execute(stmt).scalar_one_or_none()

        if user and bcrypt.check_password_hash(user.contrasena, user_password):
            return jsonify({
                "mensaje": "Inicio de sesión exitoso",
                "usuario": user.to_dict()
            }), 200
        else:
            return jsonify({"error": "Correo o contraseña inválidos"}), 401

    except Exception as e:
        print(f"Error de autenticación: {e}")
        return jsonify({"error": "Error interno del servidor", "detalle": str(e)}), 500


# RUTA POST: Cambiar contraseña por correo (SIN AUTENTICACIÓN)
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()

    if not data or 'correo' not in data or 'nueva_contraseña' not in data:
        return jsonify({"error": "Faltan campos (correo, nueva_contraseña)"}), 400

    user_correo = data['correo']
    new_password = data['nueva_contraseña']

    try:
        stmt = select(User).filter_by(correo=user_correo)
        user = db.session.execute(stmt).scalar_one_or_none()

        if user:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.contrasena = hashed_password
            db.session.commit()

            return jsonify({"mensaje": "Contraseña actualizada con éxito"}), 200
        else:
            return jsonify({"error": "Correo no encontrado"}), 404

    except Exception as e:
        db.session.rollback()
        print(f"Error de actualización de contraseña: {e}")
        return jsonify({"error": "Error al actualizar la contraseña", "detalle": str(e)}), 500


# RUTA GET: Obtener un usuario por ID
@app.route("/users/<int:id_user>")
def get_user(id_user):
    stmt = select(User).filter_by(id_usuario=id_user)
    user = db.session.execute(stmt).scalar_one_or_none()

    if user is None:
        return jsonify({"error": f"Usuario con ID {id_user} no encontrado"}), 404

    user_data = user.to_dict()

    query = request.args.get("query")
    if query:
        user_data["query"] = query

    return jsonify(user_data), 200


# RUTA POST: Crear un nuevo usuario (Registro)
@app.route("/users/", methods=["POST"])
def create_user():
    data = request.get_json()
    required_fields = ['nom_1', 'app_1', 'correo', 'contraseña']
    if any(field not in data for field in required_fields):
        return jsonify({"error": "Faltan campos obligatorios: nom_1, app_1, correo, contraseña"}), 400

    try:
        hashed_password = bcrypt.generate_password_hash(data["contraseña"]).decode('utf-8')

        new_user = User(
            nom_1=data["nom_1"],
            nom_2=data.get("nom_2"),
            app_1=data["app_1"],
            app_2=data.get("app_2"),
            correo=data["correo"],
            contrasena=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify(new_user.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        print(f"Database error: {e}")
        return jsonify({"error": "Error al crear el usuario. Revise la consola del servidor.", "detalle": str(e)}), 500


if __name__ == '__main__':
    # NECESARIO: Inicializar el contexto de la aplicación para SQLAlchemy
    with app.app_context():
        # 1. Intenta crear tablas que aún no existen.
        # Ya que la corrección fue permanente, esta línea es suficiente.
        db.create_all()

    # Obtener el puerto de la variable de entorno PORT (lo asigna Render)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)