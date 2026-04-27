# SecureShield 🔐

SecureShield is a Python-based Flask API that implements secure authentication and role-based access control using bcrypt and JSON Web Tokens (JWT).

---

## 🎓 Course Information

- **Course:** SENG 473 – Information Security  
- **Instructor:** Lect. Muhammet Mustafa Ölmez  

---

## 👥 Group Members

- Maimuna Aminu Suleiman  
- Zakariyya Zakariyya Suleiman  
- Sidi Lamine Abdourahmane  

---

## 🚀 Features

- User registration with bcrypt password hashing  
- Login with JWT token generation  
- Protected routes using token validation  
- Role-Based Access Control (User vs Admin)  
- Admin-only delete route  
- Logout using token blacklisting  
- Unauthorized access logging in `security.log`  

---

## 📁 Project Structure

```text
SecureShield/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── docs/
│   └── SecureShield_Report.pdf