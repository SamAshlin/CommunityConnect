from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import datetime
import jwt
from functools import wraps
from bson import ObjectId
from bson.objectid import ObjectId
import qrcode
from io import BytesIO
import base64
import re
import razorpay
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory
import random

otp_store = {}  # temporary store
otp_store_org = {}

UPLOAD_FOLDER = "uploads"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

razorpay_client = razorpay.Client(
    auth=("rzp_test_SNengkBygDxNPO","2oq4oxnHbwB1Dvgxt2XujExy")
)

SECRET_KEY = "community_secret_key"

app = Flask(__name__)
CORS(app)

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["community_connect"]

users_collection = db["users"]
org_collection = db["organizations"]
donation_db = db["donations"]
favorites_collection = db["favorites"]
notifications_collection = db["notifications"]

@app.route("/")
def home():
    return render_template("landing.html")


def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):

            token = request.headers.get("Authorization")

            if not token:
                return jsonify({"msg": "Token missing"}), 401

            try:
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

                # Role Check
                if role and decoded["role"] != role:
                    return jsonify({"msg": "Unauthorized access"}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({"msg": "Token expired"}), 401
            except:
                return jsonify({"msg": "Invalid token"}), 401

            return f(decoded, *args, **kwargs)

        return decorated
    return decorator

# ====================================
# DONOR REGISTRATION
# ====================================
@app.route("/register-user", methods=["POST"])
def register_user():
    data = request.json

    if users_collection.find_one({"mobile": data["mobile"]}):
        return jsonify({"msg": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(
        data["password"].encode("utf-8"),
        bcrypt.gensalt()
    )

    user_data = {
        "name": data["name"],
        "email": data["email"],
        "mobile": data["mobile"],
        "address": data["address"],
        "id_proof_type": data["idProofType"],
        "id_proof_number": data["idProofNumber"],
        "password": hashed_pw,
        "role": "donor",
        "created_at": datetime.datetime.utcnow()
    }

    users_collection.insert_one(user_data)

    return jsonify({"msg": "User registered successfully"}), 201


# ====================================
# ORGANIZATION REGISTRATION
# ====================================
@app.route("/register-org", methods=["POST"])
def register_org():
    data = request.json

    if org_collection.find_one({"registration_number": data["registrationNumber"]}):
        return jsonify({"msg": "Organization already registered"}), 400

    hashed_pw = bcrypt.hashpw(
        data["password"].encode("utf-8"),
        bcrypt.gensalt()
    )

    org_data = {
        "org_name": data["orgName"],
        "registration_number": data["registrationNumber"],
        "ngo_type": data["ngoType"],
        "contact_person": data["contactPerson"],
        "email": data["email"],
        "mobile": data["mobile"],
        "address": data["address"],
        "bank_account": data["bankAccount"],
        "ifsc": data["ifsc"],
        "upi": data["upi"],
        "description": data["description"],
        "password": hashed_pw,
        "role": "organization",
        "status": "Pending",
        "created_at": datetime.datetime.utcnow()
    }

    org_collection.insert_one(org_data)

    return jsonify({"msg": "Organization registered. Await admin approval."}), 201


# ====================================
# USER LOGIN
# ====================================
@app.route("/login-user", methods=["POST"])
def login_user():
    data = request.json

    user = users_collection.find_one({"mobile": data["mobile"]})
    if not user:
        return jsonify({"msg": "User not found"}), 404

    if not bcrypt.checkpw(data["password"].encode("utf-8"), user["password"]):
        return jsonify({"msg": "Invalid password"}), 401

    token = jwt.encode({
        "id": str(user["_id"]),
        "role": "donor",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "msg": "Login successful",
        "token": token,
        "role": "donor"
    })


# SEND OTP
@app.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.json
    mobile = data["mobile"]

    user = users_collection.find_one({"mobile": mobile})
    if not user:
        return jsonify({"msg": "User not found"}), 404

    otp = str(random.randint(100000,999999))

    otp_store[mobile] = otp

    print("OTP:", otp)  # 🔥 for now (later send SMS)

    return jsonify({"msg": "OTP sent"})


# VERIFY OTP + RESET PASSWORD
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json

    mobile = data["mobile"]
    otp = data["otp"]
    new_pass = data["newPassword"]

    if otp_store.get(mobile) != otp:
        return jsonify({"msg": "Invalid OTP"}), 400

    hashed = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())

    users_collection.update_one(
        {"mobile": mobile},
        {"$set": {"password": hashed}}
    )

    otp_store.pop(mobile, None)

    return jsonify({"msg": "Password updated successfully"})


# ====================================
# ORGANIZATION LOGIN
# ====================================
@app.route("/login-org", methods=["POST"])
def login_org():
    data = request.json

    org = org_collection.find_one({"email": data["email"]})
    if not org:
        return jsonify({"msg": "Organization not found"}), 404

    if org["status"] != "Approved":
        return jsonify({"msg": "Organization not approved yet"}), 403

    if not bcrypt.checkpw(data["password"].encode("utf-8"), org["password"]):
        return jsonify({"msg": "Invalid password"}), 401

    token = jwt.encode({
        "id": str(org["_id"]),
        "role": "organization",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "msg": "Login successful",
        "token": token,
        "role": "organization"
    })

@app.route("/send-otp-org", methods=["POST"])
def send_otp_org():
    data = request.json
    email = data["email"]

    org = org_collection.find_one({"email": email})
    if not org:
        return jsonify({"msg":"Org not found"}),404

    otp = str(random.randint(100000,999999))
    otp_store_org[email] = otp

    print("ORG OTP:", otp)

    return jsonify({"msg":"OTP sent"})


@app.route("/verify-otp-org", methods=["POST"])
def verify_otp_org():
    data = request.json

    email = data["email"]
    otp = data["otp"]

    if otp_store_org.get(email) != otp:
        return jsonify({"msg":"Invalid OTP"}),400

    hashed = bcrypt.hashpw(data["newPassword"].encode(), bcrypt.gensalt())

    org_collection.update_one(
        {"email": email},
        {"$set": {"password": hashed}}
    )

    otp_store_org.pop(email, None)

    return jsonify({"msg":"Password updated"})

@app.route("/dashboard-user", methods=["GET"])
@token_required(role="donor")
def dashboard_user(decoded):

    user = users_collection.find_one({"_id": ObjectId(decoded["id"])})

    return jsonify({
        "msg": f"Welcome {user['name']}",
        "name": user.get("name"),
        "email": user.get("email"),
        "mobile": user.get("mobile")
    })

@app.route("/dashboard-org", methods=["GET"])
@token_required(role="organization")
def dashboard_org(decoded):
    return jsonify({
        "msg": "Welcome Organization Dashboard",
        "org_id": decoded["id"]
    })

@app.route("/user-register")
def user_register_page():
    return render_template("userreg.html")


@app.route("/user-login")
def user_login_page():
    return render_template("userlogin.html")


@app.route("/user-dashboard")
def user_dashboard_page():
    return render_template("udb.html")


@app.route("/org-register")
def org_register_page():
    return render_template("orgreg.html")


@app.route("/org-login")
def org_login_page():
    return render_template("orglogin.html")


@app.route("/org-dashboard")
def org_dashboard_page():
    return render_template("odb.html")

@app.route("/admin-login")
def admin_login_page():
    return render_template("adminlogin.html")


@app.route("/admin-dashboard")
def admin_dashboard_page():
    return render_template("adb.html")

@app.route("/donate-money")
def donate_money_page():
    return render_template("donatemoney.html")

@app.route("/donate-item")
def donate_item_page():
    return render_template("itemdonate.html")


@app.route("/login-admin", methods=["POST"])
def login_admin():
    data = request.json

    # Hardcoded admin (for demo)
    if data["username"] != "admin" or data["password"] != "admin123":
        return jsonify({"msg": "Invalid admin credentials"}), 401

    token = jwt.encode({
        "role": "admin",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "msg": "Admin login successful",
        "token": token,
        "role": "admin"
    })

@app.route("/admin/pending-orgs", methods=["GET"])
@token_required(role="admin")
def get_pending_orgs(decoded):

    pending = list(org_collection.find(
        {"status": "Pending"},
        {"password": 0}   # exclude password
    ))

    for org in pending:
        org["_id"] = str(org["_id"])

    return jsonify(pending)

@app.route("/admin/approve-org/<org_id>", methods=["PUT"])
@token_required(role="admin")
def approve_org(decoded, org_id):

    org_collection.update_one(
        {"_id": ObjectId(org_id)},
        {"$set": {"status": "Approved"}}
    )

    return jsonify({"msg": "Organization Approved"})

@app.route("/admin/reject-org/<org_id>", methods=["PUT"])
@token_required(role="admin")
def reject_org(decoded, org_id):

    org_collection.update_one(
        {"_id": ObjectId(org_id)},
        {"$set": {"status": "Rejected"}}
    )

    return jsonify({"msg": "Organization Rejected"})

# CREATE DONATION REQUEST
# =========================

donation_collection = db["donation_requests"]

@app.route("/create-request", methods=["POST"])
@token_required(role="organization")
def create_request(decoded):

    data = request.get_json()

    if data["type"] == "Money":

        request_data = {
            "org_id": decoded["id"],
            "title": data["title"],
            "description": data["description"],
            "category": data["category"],
            "type": "Money",
            "amount": int(data["amount"]),
            "received_amount": 0,
            "location": data["location"],
            "status": "Open",
            "created_at": datetime.datetime.utcnow()
        }

    else:

        request_data = {
            "org_id": decoded["id"],
            "title": data["title"],
            "description": data["description"],
            "category": data["category"],
            "type": "Items",
            "items_description": data["items_description"],
            "quantity": int(data["quantity"]),
            "equivalent_amount": int(data["equivalent_amount"]),
            "received_amount": 0,
            "received_quantity": 0,
            "received_money": 0,
            "location": data["location"],
            "status": "Open",
            "created_at": datetime.datetime.utcnow()
        }

    donation_collection.insert_one(request_data)

    return jsonify({"msg": "Request created successfully"})

# =========================
# GET ALL DONATION REQUESTS
# =========================
@app.route("/my-requests", methods=["GET"])
@token_required(role="organization")
def my_requests(decoded):

    requests = list(donation_collection.find({
        "org_id": decoded["id"]
    }))

    result = []

    for r in requests:
        r["_id"] = str(r["_id"])
        result.append(r)

    return jsonify(result)

@app.route("/donations/<request_id>")
@token_required(role="organization")
def get_donations(decoded, request_id):

    donations = list(donation_db.find({"request_id": request_id}))

    result = []

    for d in donations:

        user = users_collection.find_one({"_id": ObjectId(d["donor_id"])})

        if d.get("type") == "Items" and d.get("status") != "Completed":
            continue   # ✅ only show completed item donations

        result.append({
            "name": user["name"] if user else "Anonymous",
            "amount": d.get("amount", 0),
            "type": d.get("type"),
            "quantity": d.get("quantity"),
            "status": d.get("status")
        })

    return jsonify(result)

@app.route("/my-donations")
@token_required(role="donor")
def my_donations(decoded):

    d = list(donation_db.find({"donor_id": decoded["id"]}))

    result = []

    for i in d:
        try:
            req = donation_collection.find_one({"_id": ObjectId(i["request_id"])})
        except:
            req = None

        # ✅ Handle both types
        if i.get("type") == "Items":
            amount_text = f"{i.get('quantity', 0)} items"
        else:
            amount_text = f"₹{i.get('amount', 0)}"

        result.append({
        "title": req["title"] if req else "Unknown",
        "type": i.get("type"),
        "amount": i.get("amount"),
        "quantity": i.get("quantity"),
        "status": i.get("status", "Success"),
        "date": i.get("created_at").strftime("%d %b %Y")
        })

    return jsonify(result)

@app.route("/toggle-favorite/<request_id>", methods=["POST"])
@token_required(role="donor")
def toggle_favorite(decoded, request_id):

    user_id = decoded["id"]

    existing = favorites_collection.find_one({
        "user_id": user_id,
        "request_id": request_id
    })

    if existing:
        favorites_collection.delete_one({"_id": existing["_id"]})
        return jsonify({"msg": "Removed from favorites"})
    else:
        favorites_collection.insert_one({
            "user_id": user_id,
            "request_id": request_id
        })
        return jsonify({"msg": "Added to favorites"})

@app.route("/my-favorites")
@token_required(role="donor")
def get_favorites(decoded):

    user_id = decoded["id"]

    favs = list(favorites_collection.find({"user_id": user_id}))

    result = []

    for f in favs:
        req = donation_collection.find_one({"_id": ObjectId(f["request_id"])})
        if req:
            req["_id"] = str(req["_id"])
            result.append(req)

    return jsonify(result)

@app.route("/add-notification", methods=["POST"])
@token_required(role="donor")
def add_notification(decoded):

    data = request.get_json()

    notifications_collection.insert_one({
        "user_id": decoded["id"],
        "text": data["text"],
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"msg":"Notification added"})


@app.route("/my-notifications")
@token_required(role="donor")
def get_notifications(decoded):

    notes = list(notifications_collection.find({
        "user_id": decoded["id"]
    }).sort("created_at", -1))

    for n in notes:
        n["_id"] = str(n["_id"])

    return jsonify(notes)

@app.route("/donate-items", methods=["POST"])
@token_required(role="donor")
def donate_items(decoded):

    request_id = request.form.get("request_id")
    quantity = int(request.form.get("quantity"))
    method = request.form.get("method")

    address = request.form.get("address")
    date = request.form.get("date")
    time = request.form.get("time")

    file = request.files.get("proof")

    file_path = None

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        file.save(file_path)

    donation_db.insert_one({
        "request_id": request_id,
        "donor_id": decoded["id"],
        "quantity": quantity,
        "type": "Items",
        "method": method,
        "address": address,
        "date": date,
        "time": time,
        "proof": file_path,
        "status": "Pending",
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"msg":"Item donation submitted successfully"})

@app.route("/org-item-donations", methods=["GET"])
@token_required(role="organization")
def org_item_donations(decoded):

    donations = list(donation_db.find({
    "type": "Items",
    "status": {"$ne": "Completed"}   # ✅ hide completed
    }).sort("created_at", -1))

    result = []

    for d in donations:

        req = donation_collection.find_one({"_id": ObjectId(d["request_id"])})
        user = users_collection.find_one({"_id": ObjectId(d["donor_id"])})

        result.append({
            "_id": str(d["_id"]),
            "request_title": req["title"] if req else "Unknown",
            "donor_name": user["name"] if user else "Anonymous",
            "quantity": d["quantity"],
            "method": d["method"],
            "status": d["status"],
            "address": d.get("address"),
            "date": d.get("date"),
            "time": d.get("time"),
            "proof": d.get("proof")
        })

    return jsonify(result)

@app.route("/update-item-status", methods=["POST"])
@token_required(role="organization")
def update_item_status(decoded):

    data = request.json

    donation_id = data["donation_id"]
    status = data["status"]

    donation = donation_db.find_one({"_id": ObjectId(donation_id)})

    if not donation:
        return jsonify({"msg":"Not found"}),404

    donation_db.update_one(
        {"_id": ObjectId(donation_id)},
        {"$set": {"status": status}}
    )

    req = donation_collection.find_one({"_id": ObjectId(donation["request_id"])})

    if status == "Completed":

        per_item_value = req.get("equivalent_amount", 0) / max(req.get("quantity", 1),1)

        donation_collection.update_one(
            {"_id": ObjectId(donation["request_id"])},
            {
            "$inc": {
                "received_quantity": donation["quantity"],
                "received_money": donation["quantity"] * per_item_value
            }
            }
        )

    # ✅ Notification (safe now)
    notifications_collection.insert_one({
    "user_id": donation["donor_id"],
    "text": f"Your item donation for '{req['title']}' is {status}" if req else f"Your item donation is {status}",
    "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"msg":"Status updated"})

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory("uploads", filename)


@app.route("/requests", methods=["GET"])
@token_required(role="donor")
def get_requests(decoded):

    requests = list(donation_collection.find({"status": "Open"}))

    results = []

    for r in requests:

        org = org_collection.find_one({"_id": ObjectId(r["org_id"])})

        if r["type"] == "Money":
            received = r.get("received_amount", 0)
            total = r.get("amount", 0)
            percent = int((received / total) * 100) if total > 0 else 0

            results.append({
            "_id": str(r["_id"]),
            "title": r["title"],
            "description": r["description"],
            "type": r["type"],
            "amount": total,
            "received": received,
            "percent": percent,
            "org_name": org["org_name"] if org else "Unknown"
            })

        else:
            received_qty = r.get("received_quantity", 0)
            received_money = r.get("received_money", 0)
            total_qty = r.get("quantity", 0)
            total_money = r.get("equivalent_amount", 0)

            percent = int((received_money / total_money) * 100) if total_money > 0 else 0

            results.append({
            "_id": str(r["_id"]),
            "title": r["title"],
            "description": r["description"],
            "type": r["type"],
            "items_description": r.get("items_description"),
            "received_qty": received_qty,
            "received_money": received_money,
            "total_qty": total_qty,
            "total_money": total_money,
            "percent": percent,
            "org_name": org["org_name"] if org else "Unknown"
            })

    return jsonify(results)

@app.route("/request/<request_id>", methods=["GET"])
@token_required(role="donor")
def get_single_request(decoded, request_id):

    req = donation_collection.find_one({"_id": ObjectId(request_id)})

    if not req:
        return jsonify({"msg": "Request not found"}), 404

    org = org_collection.find_one({"_id": ObjectId(req["org_id"])})

    data = {
        "_id": str(req["_id"]),
        "title": req["title"],
        "description": req["description"],
        "category": req["category"],
        "type": req["type"],
        "quantity": req.get("quantity"),
        "amount": req.get("amount"),
        "items_description": req.get("items_description"),
        "location": req["location"],
        "equivalent_amount": req.get("equivalent_amount"),
        "created_at": req["created_at"].strftime("%d %B %Y"),
        "org_name": org["org_name"] if org else "Unknown"
    }

    return jsonify(data)

@app.route("/request-payment/<request_id>", methods=["GET"])
@token_required(role="donor")
def get_payment_request(decoded, request_id):

    req = donation_collection.find_one({"_id": ObjectId(request_id)})

    if not req:
        return jsonify({"msg":"Request not found"}),404

    org = org_collection.find_one({"_id": ObjectId(req["org_id"])})

    if req["type"] == "Money":
        requested = req.get("amount", 0)
    else:
        requested = req.get("equivalent_amount", 0)

    return jsonify({
    "title": req["title"],
    "org_name": org["org_name"],
    "upi": org["upi"],
    "requested_money": requested,
    "location": req["location"]
    })


@app.route("/create-order", methods=["POST"])
@token_required(role="donor")
def create_order(decoded):

    data = request.get_json()

    amount = int(data["amount"]) * 100  # convert to paise

    order = razorpay_client.order.create({
        "amount": amount,
        "currency": "INR",
        "payment_capture": 1
    })

    return jsonify({
        "order_id": order["id"],
        "amount": amount
    })

@app.route("/verify-payment", methods=["POST"])
@token_required(role="donor")
def verify_payment(decoded):

    data = request.get_json()

    payment_id = data["payment_id"]
    request_id = data["request_id"]

    payment = razorpay_client.payment.fetch(payment_id)

    if payment["status"] != "captured":
        return jsonify({"msg":"Payment not verified"}),400

    amount = payment["amount"] / 100

    donation_db.insert_one({
    "request_id": request_id,
    "donor_id": decoded["id"],
    "payment_id": payment_id,
    "amount": amount,
    "type": "Money",   # ✅ ADD THIS
    "gateway": "razorpay",
    "status": "Success",
    "created_at": datetime.datetime.utcnow()
    })

    donation_collection.update_one(
        {"_id": ObjectId(request_id)},
        {"$inc": {"received_amount": amount}}
    )

    return jsonify({"msg":"Donation successful"})


@app.route("/create-qr", methods=["POST"])
@token_required(role="donor")
def create_qr(decoded):

    data = request.get_json()

    if not data["amount"]:
      return jsonify({"msg":"Enter donation amount"}),400

    request_id = data["request_id"]
    amount = int(data["amount"]) * 100

    req = donation_collection.find_one({"_id": ObjectId(request_id)})

    org = org_collection.find_one({"_id": ObjectId(req["org_id"])})

    qr = razorpay_client.qrcode.create({
        "type": "upi_qr",
        "name": org["org_name"],
        "usage": "single_use",
        "fixed_amount": True,
        "payment_amount": amount,
        "description": "Community Connect Donation"
    })

    return jsonify({
        "qr_id": qr["id"],
        "qr_image": qr["image_url"],
        "upi": org["upi"]
    })

@app.route("/check-qr/<qr_id>")
def check_qr(qr_id):

    payments = razorpay_client.qrcode.fetch_all_payments(qr_id)

    if payments["count"] > 0:

        payment = payments["items"][0]

        if payment["status"] == "captured":
            return jsonify({
                "paid": True,
                "payment_id": payment["id"],
                "amount": payment["amount"]/100
            })

    return jsonify({"paid": False})

#TEMPORARY CHECK

@app.route("/generate-qr/<request_id>/<amount>")
def generate_qr(request_id, amount):

    # Find the donation request
    donation = donation_collection.find_one({"_id": ObjectId(request_id)})

    if not donation:
        return jsonify({"msg":"Invalid request"}),404

    # Get organization
    org = org_collection.find_one({"_id": ObjectId(donation["org_id"])})

    if not org:
        return jsonify({"msg":"Organization not found"}),404

    upi_id = org["upi"]

    upi_link = f"upi://pay?pa={upi_id}&pn={org['org_name']}&am={amount}&cu=INR"

    qr = qrcode.make(upi_link)

    buffer = BytesIO()
    qr.save(buffer)

    img_str = base64.b64encode(buffer.getvalue()).decode()

    return jsonify({
        "qr": img_str,
        "upi": upi_id
    })
@app.route("/verify-pay", methods=["POST"])
@token_required(role="donor")
def verify_pay(decoded):

    data = request.get_json()

    txn_id = data["payment_id"]
    request_id = data["request_id"]
    amount = float(data.get("amount", 0))

    if not re.match(r'^[A-Za-z0-9]{6,20}$', txn_id):
        return jsonify({"msg": "Invalid transaction ID"}), 400

    existing = donation_db.find_one({"payment_id": txn_id})
    if existing:
        return jsonify({"msg": "Transaction already used"}), 400

    if amount <= 0:
        return jsonify({"msg": "Invalid donation amount"}), 400

    donation_db.insert_one({
        "request_id": request_id,
        "donor_id": decoded["id"],
        "type": "Money",
        "payment_id": txn_id,
        "amount": amount,
        "gateway": "UPI",
        "status": "Success",
        "created_at": datetime.datetime.utcnow()
    })

    donation_collection.update_one(
        {"_id": ObjectId(request_id)},
        {"$inc": {"received_amount": amount}}
    )

    return jsonify({"msg": "Donation successful"})

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response

if __name__ == "__main__":
    app.run(debug=True, port=5000)