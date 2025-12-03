from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
from sqlalchemy import select, text, func, desc
from flask_bcrypt import Bcrypt
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
    contrasena = db.Column(db.String(255), nullable=False)

    def to_dict(self):
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

    id_subasta = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)

    fecha_ini = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_fin = db.Column(db.DateTime)
    descripcion = db.Column(db.Text)

    titulo = db.Column(db.String(255), nullable=False)  # Nueva columna para el título
    precio_base = db.Column(db.Numeric(10, 2))
    url_imgs = db.Column(db.Text)  # URLs separadas por coma

    estado = db.Column(db.Integer, default=1, nullable=False)

    creador = db.relationship('User', backref=db.backref('mis_subastas', lazy=True))
    pujas = db.relationship('Puja', backref='subasta_rel', lazy=True)


    def get_puja_actual(self):
        puja_mas_alta = db.session.execute(
            select(Puja)
            .filter(Puja.id_subasta == self.id_subasta)
            .order_by(desc(Puja.puja), desc(Puja.fecha_puja))
            .limit(1)
        ).scalar_one_or_none()

        if puja_mas_alta:
            return {
                "monto": str(puja_mas_alta.puja),
                "id_usuario_pujador": puja_mas_alta.id_usuario,
                "fecha": puja_mas_alta.fecha_puja.isoformat()
            }

        return {
            "monto": str(self.precio_base),
            "id_usuario_pujador": None,
            "fecha": None
        }

    
    def to_dict(self):
        urls_list = self.url_imgs.split(',') if self.url_imgs else []

        return {
            "id_subasta": self.id_subasta,
            "id_usuario_creador": self.id_usuario,
            "titulo": self.titulo,
            "fecha_ini": self.fecha_ini.isoformat() if self.fecha_ini else None,
            "fecha_fin": self.fecha_fin.isoformat() if self.fecha_fin else None,
            "descripcion": self.descripcion,
            "precio_base": str(self.precio_base),
            "estado": self.estado,

            # ← aquí devolvemos EXACTAMENTE lo que quieres
            "urls_imagenes": urls_list,

            "puja_actual": self.get_puja_actual()
        }

class Puja(db.Model):
    __tablename__ = 'puja'

    id_puja = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=False)
    id_subasta = db.Column(db.Integer, db.ForeignKey('subasta.id_subasta'), nullable=False)

    puja = db.Column(db.Numeric(10, 2), nullable=False)
    fecha_puja = db.Column(db.DateTime, default=datetime.utcnow)

    usuario_pujador = db.relationship('User', backref=db.backref('mis_pujas', lazy=True))

    def to_dict(self):
        return {
            "id_puja": self.id_puja,
            "id_usuario_pujador": self.id_usuario,
            "id_subasta": self.id_subasta,
            "monto": str(self.puja),
            "fecha": self.fecha_puja.isoformat() if self.fecha_puja else None
        }


class Imagen(db.Model):
    __tablename__ = 'imagen'
    id_imagen = db.Column(db.Integer, primary_key=True)
    id_subasta = db.Column(db.Integer, db.ForeignKey('subasta.id_subasta'), nullable=False)
    datos_imagen = db.Column(db.LargeBinary)

    def to_dict(self):
        return {
            "id_imagen": self.id_imagen,
            "id_subasta": self.id_subasta,
            "datos_imagen_base64": self.datos_imagen.decode('utf-8')[:50] + '...' if self.datos_imagen else None
        }


# ======================================================
# RUTAS DE LA API
# ======================================================

@app.route('/')
def root():
    return jsonify("Hola jotos")


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
        return jsonify({"error": "Error al actualizar la contraseña", "detalle": str(e)}), 500


@app.route("/users/<int:id_user>", methods=["GET"])
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


# RUTA PUT: Modificar datos de usuario (NUEVA)
@app.route("/users/<int:id_user>", methods=["PUT"])
def update_user(id_user):
    user = db.session.get(User, id_user)
    if not user:
        return jsonify({"error": f"Usuario con ID {id_user} no encontrado"}), 404

    data = request.get_json()

    # Actualizar campos solo si vienen en el JSON
    if 'nom_1' in data:
        user.nom_1 = data['nom_1']
    if 'nom_2' in data:
        user.nom_2 = data['nom_2']
    if 'app_1' in data:
        user.app_1 = data['app_1']
    if 'app_2' in data:
        user.app_2 = data['app_2']
    if 'correo' in data:
        # Opcional: Validar que el nuevo correo no exista ya
        existing_user = db.session.execute(select(User).filter_by(correo=data['correo'])).scalar_one_or_none()
        if existing_user and existing_user.id_usuario != id_user:
            return jsonify({"error": "El correo ya está en uso por otro usuario"}), 400
        user.correo = data['correo']

    try:
        db.session.commit()
        return jsonify({"mensaje": "Usuario actualizado correctamente", "usuario": user.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al actualizar usuario", "detalle": str(e)}), 500


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


# === RUTAS DE SUBASTAS ===

@app.route("/subastas", methods=["GET", "POST"])
def handle_subastas():
    if request.method == "POST":
        data = request.get_json()
        required_fields = ['id_usuario', 'fecha_fin', 'descripcion', 'precio_base']
        if any(field not in data for field in required_fields):
            return jsonify({"error": "Faltan campos obligatorios para la subasta"}), 400

        if not db.session.get(User, data['id_usuario']):
            return jsonify({"error": "ID de usuario creador no encontrado"}), 404

        try:
            fecha_fin = datetime.fromisoformat(data['fecha_fin'])

            # NUEVO: manejar lista de URLs
            urls_list = data.get("urls_imagenes", [])
            urls_string = ",".join(urls_list) if isinstance(urls_list, list) else ""

            nueva_subasta = Subasta(
                id_usuario=data['id_usuario'],
                fecha_fin=fecha_fin,
                descripcion=data['descripcion'],
                precio_base=data['precio_base'],
                estado=1,
                urls_imagenes=urls_string  # NUEVO
            )

            db.session.add(nueva_subasta)
            db.session.commit()
            return jsonify(nueva_subasta.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error al crear subasta: {e}")
            return jsonify({"error": "Error al crear subasta", "detalle": str(e)}), 500

    else:  # GET
        stmt = select(Subasta).filter_by(estado=1)
        subastas = db.session.execute(stmt).scalars().all()
        return jsonify([s.to_dict() for s in subastas]), 200

# RUTA PUT: Actualizar precio base de subasta
@app.route("/subastas/<int:id_subasta>", methods=["PUT"])
def update_subasta(id_subasta):
    subasta = db.session.get(Subasta, id_subasta)

    if not subasta or subasta.estado == 0:
        return jsonify({"error": "Subasta no encontrada o inactiva"}), 404

    data = request.get_json()
    if 'precio_base' not in data:
        return jsonify({"error": "Falta el campo 'precio_base'"}), 400

    try:
        subasta.precio_base = data['precio_base']
        db.session.commit()
        return jsonify({"mensaje": "Precio base actualizado", "subasta": subasta.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al actualizar subasta", "detalle": str(e)}), 500


# RUTA PUT: Dar de baja una subasta
@app.route("/subastas/<int:id_subasta>/baja", methods=["PUT"])
def baja_subasta(id_subasta):
    subasta = db.session.get(Subasta, id_subasta)

    if not subasta:
        return jsonify({"error": "Subasta no encontrada"}), 404

    if subasta.estado == 0:
        return jsonify({"mensaje": "La subasta ya estaba dada de baja"}), 200

    try:
        subasta.estado = 0
        db.session.commit()
        return jsonify(
            {"mensaje": "Subasta dada de baja correctamente (Borrado Lógico)", "id_subasta": id_subasta}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Error al dar de baja la subasta", "detalle": str(e)}), 500


@app.route("/subastas/<int:id_subasta>/pujas", methods=["GET", "POST"])
def handle_pujas(id_subasta):
    subasta = db.session.get(Subasta, id_subasta)

    if not subasta or subasta.estado == 0:
        return jsonify({"error": "Subasta no encontrada o inactiva"}), 404

    if request.method == "POST":
        data = request.get_json()
        required_fields = ['id_usuario', 'puja']
        if any(field not in data for field in required_fields):
            return jsonify({"error": "Faltan campos obligatorios para la puja"}), 400

        puja_actual_data = subasta.get_puja_actual()

        if float(data['puja']) <= float(puja_actual_data['monto']):
            return jsonify({"error": f"La puja debe ser mayor que el monto actual ({puja_actual_data['monto']})"}), 400

        try:
            nueva_puja = Puja(
                id_usuario=data['id_usuario'],
                id_subasta=id_subasta,
                puja=data['puja']
            )
            db.session.add(nueva_puja)
            db.session.commit()
            return jsonify(nueva_puja.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error al crear puja: {e}")
            return jsonify({"error": "Error al crear puja", "detalle": str(e)}), 500

    else:  # GET
        stmt = select(Puja).filter_by(id_subasta=id_subasta).order_by(Puja.puja.desc())
        pujas = db.session.execute(stmt).scalars().all()
        return jsonify([p.to_dict() for p in pujas]), 200


@app.route("/subastas/<int:id_subasta>/imagenes", methods=["GET", "POST"])
def handle_imagenes(id_subasta):
    subasta = db.session.get(Subasta, id_subasta)

    if not subasta or subasta.estado == 0:
        return jsonify({"error": "Subasta no encontrada o inactiva"}), 404

    if request.method == "POST":
        data = request.get_json()
        if not data or 'datos_imagen_base64' not in data:
            return jsonify({"error": "Faltan datos de la imagen (datos_imagen_base64)"}), 400

        try:
            datos_bytes = data['datos_imagen_base64'].encode('utf-8')
            nueva_imagen = Imagen(
                id_subasta=id_subasta,
                datos_imagen=datos_bytes
            )
            db.session.add(nueva_imagen)
            db.session.commit()
            return jsonify({"mensaje": "Imagen subida con éxito", "id_imagen": nueva_imagen.id_imagen}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error al subir imagen: {e}")
            return jsonify({"error": "Error al subir imagen", "detalle": str(e)}), 500

    else:  # GET
        stmt = select(Imagen).filter_by(id_subasta=id_subasta)
        imagenes = db.session.execute(stmt).scalars().all()
        return jsonify([i.to_dict() for i in imagenes]), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)