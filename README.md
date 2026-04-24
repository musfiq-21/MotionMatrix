#  MotionMatrix – Hand Activity Detection System

##  Overview
**MotionMatrix** is a prototype system designed to automate productivity tracking in garment factories using computer vision and role-based workflow management.

The system detects worker activity using CCTV footage in a **controlled environment** (single worker per frame, close camera placement) and integrates it with a **full-stack web platform** for monitoring, reporting, and communication. (This is a prototype and not intended for real-world deployment without further optimization.)

---

##  Objectives
- Automate worker activity monitoring
- Detect idle vs active time using hand movement
- Manage workforce operations (leave, overtime, reporting)
- Provide role-based dashboards and communication

---

## 👥 Stakeholders & Roles

| Role | Responsibilities |
|------|----------------|
| **System Admin** | User management, role assignment, system configuration |
| **Owner** | View overall production trends, download reports |
| **Manager** | Monitor productivity, attendance, and reports |
| **Floor Manager** | Manage workers, monitor activity, handle leaves |
| **Worker** | Request leave, perform assigned tasks |

---

##  Core Features

###  Authentication & Authorization
- Admin registers all users
- Role-based access control (RBAC)
- Only admin can reset passwords
- User deactivation supported

---

###  In-App Messaging System
Role-based communication:

- Worker → Floor Manager  
- Floor Manager → Worker, Manager, Admin  
- Manager → Floor Manager, Owner, Admin  
- Owner → Manager, Admin  

---

###  Infrastructure Management
- Create and manage **floors**
- Assign **CCTV cameras** to floors
- Each camera is assigned to only one workstation
- No camera can belong to multiple floors

---

###  Productivity & Payroll Management
- Daily production entry by floor managers
- Historical performance tracking

#### Reports:
- CSV export
- PDF export
- Graphs (Bar chart, Pie chart)

#### Worker Profile Tracks:
- Active time
- Idle time
- Overtime

---

###  Overtime System
- Configurable shift end time (default: 5:00 PM)
- Floor manager approves overtime
- Overtime = work done after shift end
**Formula:** Overtime Pay = Overtime Hours × Hourly Wage

---

###  Leave Management
- Workers request leave via in-app messaging
- Floor manager:
  - Approves/rejects leave
  - Sets leave duration and reason
- Replacement workers assigned from reserve pool

---

###  Activity Detection System
- One CCTV camera per workstation
- Hand movement detection used for activity tracking

#### Detection Logic:
- No movement for configured time → **Idle**
- No tracking during:
  - Lunch breaks
  - After working hours

- Real-time idle alerts sent to floor manager dashboard

---

##  Tech Stack

### Frontend
- React.js
- Role-based dashboards
- Dynamic UI updates

### Backend
- Node.js (Express.js)
- REST API architecture
- Authentication & authorization
- WebSocket for real-time messaging and notifications

### Database
- PostgreSQL
- Stores:
  - Users & roles
  - Attendance
  - Activity logs
  - Production data
  - Leave records

### Machine Learning (Prototype)
- Hand activity detection (Idle vs Active)

---

##  System Architecture (High Level)
CCTV Camera → Local Machine → ML Processing
                          ↓
                    Node.js Backend
                          ↓
                    PostgreSQL DB
                          ↓
                     React Frontend


---

##  Workflow Summary

1. Admin registers users
2. Users log in and change OTP password
3. System tracks activity:
   - Active / Idle / Absent
4. Floor manager monitors real-time dashboard
5. Worker sends leave request via messaging
6. Floor manager processes leave
7. Manager/Owner analyze reports
8. Overtime and payroll calculated automatically

---

##  Limitations
- Works only in controlled environments
- Assumes single worker per frame
- Not suitable for large-scale deployment
- ML model is not production optimized

---

##  Future Improvements
- Multi-worker detection support
- Improved ML accuracy
- Cloud deployment (AWS/GCP)
- Mobile application
- Advanced analytics dashboard

---

##  Contributors
- SPL-2 Project Team

---

##  License
This project is intended for academic and prototype purposes only.
