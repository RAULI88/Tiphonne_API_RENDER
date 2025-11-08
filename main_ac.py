from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
from sqlalchemy import select, text  # Necesario para consultas modernas y SQL puro
from flask_bcrypt import Bcrypt  # Necesario para hashear contraseñas
from flask_cors import CORS
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




# --- 3. DEFINICIÓN DEL MODELO ---
class User(db.Model):
    # Nombre exacto de tu tabla en MySQL
    __tablename__ = 'usuario'

    # Mapeo de columnas
    id_usuario = db.Column(db.Integer, primary_key=True)
    nom_1 = db.Column(db.String(50), nullable=False)
    nom_2 = db.Column(db.String(50))
    app_1 = db.Column(db.String(50), nullable=False)
    app_2 = db.Column(db.String(50))
    correo = db.Column(db.String(120), unique=True, nullable=False)
    # CLAVE: Columna que coincide con el nombre de la DB (contrasena, sin tilde)
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

    # 1. Validar que se recibieron correo y contraseña
    if not data or 'correo' not in data or 'contraseña' not in data:
        return jsonify({"error": "Faltan campos (correo, contraseña)"}), 400

    user_correo = data['correo']
    user_password = data['contraseña']

    try:
        # 2. Buscar usuario por correo electrónico (debe ser único)
        stmt = select(User).filter_by(correo=user_correo)
        user = db.session.execute(stmt).scalar_one_or_none()

        # 3. Verificar si el usuario existe y si la contraseña coincide
        if user and bcrypt.check_password_hash(user.contrasena, user_password):
            # Éxito: Contraseña y usuario correctos
            return jsonify({
                "mensaje": "Inicio de sesión exitoso",
                "usuario": user.to_dict()
            }), 200
        else:
            # Fallo: Usuario no encontrado o contraseña incorrecta
            return jsonify({"error": "Correo o contraseña inválidos"}), 401  # 401 Unauthorized

    except Exception as e:
        print(f"Error de autenticación: {e}")
        return jsonify({"error": "Error interno del servidor", "detalle": str(e)}), 500


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
        # 2. Hashear la contraseña por seguridad
        hashed_password = bcrypt.generate_password_hash(data["contraseña"]).decode('utf-8')

        # 3. Crear el nuevo objeto para guardar
        new_user = User(
            nom_1=data["nom_1"],
            nom_2=data.get("nom_2"),
            app_1=data["app_1"],
            app_2=data.get("app_2"),
            correo=data["correo"],
            # CLAVE: Asignar al nombre de columna correcto (contrasena)
            contrasena=hashed_password
        )

        # 4. Guardar en la base de datos
        db.session.add(new_user)
        db.session.commit()

        # 5. Devolver la respuesta exitosa
        return jsonify(new_user.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        print(f"Database error: {e}")
        return jsonify({"error": "Error al crear el usuario. Revise la consola del servidor.", "detalle": str(e)}), 500


if __name__ == '__main__':
    # NECESARIO: Inicializar el contexto de la aplicación para SQLAlchemy



    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)