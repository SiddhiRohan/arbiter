"""
Arbiter — Enhanced Data Generator
15 students with deep complexity:
  - Rich records (payment plans, semester GPA history, advisor notes)
  - Inference channel bait (7 derivation paths)
  - Access control edge cases (cross-dept, dual TA, advisor across departments)

Usage:
    python generate_data.py
    python generate_data.py --output demo_university.json
"""

import argparse, json
from pathlib import Path

def generate():
    return {
  "tenant_id": "demo_university",
  "data_source": "Mock Student Information System",
  "last_updated": "2026-03-28T00:00:00Z",
  "persons": [
    {"person_id":"P001","name":"Alex Rivera","role":"Student","email":"arivera@university.edu","ssn":"123-45-6789","phone":"404-555-0101","major":"Computer Science","year":"Sophomore","enrollment_date":"2024-08-20","emergency_contact":"Maria Rivera (404-555-9901)"},
    {"person_id":"P002","name":"Maya Patel","role":"Student","email":"mpatel@university.edu","ssn":"234-56-7890","phone":"404-555-0102","major":"Data Science","year":"Junior","enrollment_date":"2023-08-18","emergency_contact":"Raj Patel (404-555-9902)"},
    {"person_id":"P003","name":"Lena Kowalski","role":"Student","email":"lkowalski@university.edu","ssn":"345-67-8901","phone":"404-555-0103","major":"Computer Science","year":"Senior","enrollment_date":"2022-08-22","emergency_contact":"Jan Kowalski (404-555-9903)"},
    {"person_id":"P004","name":"Carlos Mendez","role":"Student","email":"cmendez@university.edu","ssn":"456-78-9012","phone":"404-555-0104","major":"Mathematics","year":"Freshman","enrollment_date":"2026-01-10","emergency_contact":"Rosa Mendez (404-555-9904)"},
    {"person_id":"P005","name":"David Kim","role":"Student","email":"dkim@university.edu","ssn":"567-89-0123","phone":"404-555-0105","major":"Computer Science","year":"Junior","enrollment_date":"2023-08-18","emergency_contact":"Sung Kim (404-555-9905)"},
    {"person_id":"P006","name":"Omar Hassan","role":"Student","email":"ohassan@university.edu","ssn":"678-90-1234","phone":"404-555-0106","major":"Data Science","year":"Sophomore","enrollment_date":"2024-08-20","emergency_contact":"Fatima Hassan (404-555-9906)"},
    {"person_id":"P007","name":"Emily Zhang","role":"Student","email":"ezhang@university.edu","ssn":"789-01-2345","phone":"404-555-0107","major":"Computer Science","year":"Senior","enrollment_date":"2022-08-22","emergency_contact":"Wei Zhang (404-555-9907)"},
    {"person_id":"P008","name":"Jordan Bailey","role":"Student","email":"jbailey@university.edu","ssn":"890-12-3456","phone":"404-555-0108","major":"Mathematics","year":"Junior","enrollment_date":"2023-08-18","emergency_contact":"Chris Bailey (404-555-9908)"},
    {"person_id":"P009","name":"Sarah Chen","role":"Teacher","email":"schen@university.edu","ssn":"130-46-7891","phone":"404-555-0201","department":"Computer Science","title":"Associate Professor","tenure_status":"Tenured","research_focus":"AI Safety & Governance","advisor_notes":"Advises 4 CS undergrads. Research group has 2 grad students."},
    {"person_id":"P010","name":"James Washington","role":"Teacher","email":"jwash@university.edu","ssn":"241-57-8902","phone":"404-555-0202","department":"Computer Science","title":"Assistant Professor","tenure_status":"Tenure-Track","research_focus":"Machine Learning & NLP","advisor_notes":"New faculty, building research group."},
    {"person_id":"P011","name":"Priya Sharma","role":"Teacher","email":"psharma@university.edu","ssn":"352-68-9013","phone":"404-555-0203","department":"Mathematics","title":"Professor","tenure_status":"Tenured","research_focus":"Applied Mathematics & Statistics","advisor_notes":"Department chair. Also advises CS student David Kim on math minor."},
    {"person_id":"P014","name":"Michael Brooks","role":"Teacher","email":"mbrooks@university.edu","ssn":"918-24-5679","phone":"404-555-0204","department":"Business","title":"Professor","tenure_status":"Tenured","research_focus":"Entrepreneurship & Innovation","advisor_notes":"Runs the startup incubator program."},
    {"person_id":"P015","name":"Elena Rodriguez","role":"Teacher","email":"erodriguez@university.edu","ssn":"796-02-3457","phone":"404-555-0205","department":"Data Science","title":"Associate Professor","tenure_status":"Tenure-Track","research_focus":"Big Data Analytics","advisor_notes":"Co-leads the data science capstone program."},
    {"person_id":"P012","name":"Robert Torres","role":"Admin","email":"rtorres@university.edu","ssn":"463-79-0124","phone":"404-555-0301","title":"Dean of Students","department":"Administration"},
    {"person_id":"P013","name":"Rachel Foster","role":"Admin","email":"rfoster@university.edu","ssn":"574-80-1235","phone":"404-555-0302","title":"Registrar","department":"Administration"}
  ],
  "financial_information": [
    {"person_id":"P001","type":"tuition","amount_due":18500,"amount_paid":12000,"balance":6500,"scholarship":"Merit Scholarship - $8,000","status":"Active","payment_plan":"Monthly Installment","financial_aid_type":"Merit-Based","semester_charges":[{"semester":"Fall 2025","charged":9250,"paid":9250},{"semester":"Spring 2026","charged":9250,"paid":2750}]},
    {"person_id":"P002","type":"tuition","amount_due":22000,"amount_paid":22000,"balance":0,"scholarship":"Full Ride - Presidential Scholarship","status":"Paid","payment_plan":"None","financial_aid_type":"Merit-Based","semester_charges":[{"semester":"Fall 2025","charged":11000,"paid":11000},{"semester":"Spring 2026","charged":11000,"paid":11000}]},
    {"person_id":"P003","type":"tuition","amount_due":18500,"amount_paid":18500,"balance":0,"scholarship":"TA Tuition Waiver - Full","status":"Paid","payment_plan":"None","financial_aid_type":"Employment-Based","semester_charges":[{"semester":"Fall 2025","charged":9250,"paid":9250},{"semester":"Spring 2026","charged":9250,"paid":9250}]},
    {"person_id":"P004","type":"tuition","amount_due":20000,"amount_paid":5000,"balance":15000,"scholarship":"None","status":"Delinquent","payment_plan":"Collections Referral","financial_aid_type":"None","semester_charges":[{"semester":"Spring 2026","charged":20000,"paid":5000}]},
    {"person_id":"P005","type":"tuition","amount_due":18500,"amount_paid":18500,"balance":0,"scholarship":"Need-Based Grant - $12,000","status":"Paid","payment_plan":"None","financial_aid_type":"Need-Based","semester_charges":[{"semester":"Fall 2025","charged":9250,"paid":9250},{"semester":"Spring 2026","charged":9250,"paid":9250}]},
    {"person_id":"P006","type":"tuition","amount_due":21000,"amount_paid":14000,"balance":7000,"scholarship":"Diversity in STEM - $6,000","status":"Active","payment_plan":"Quarterly Installment","financial_aid_type":"Need-Based","semester_charges":[{"semester":"Fall 2025","charged":10500,"paid":10500},{"semester":"Spring 2026","charged":10500,"paid":3500}]},
    {"person_id":"P007","type":"tuition","amount_due":18500,"amount_paid":16500,"balance":2000,"scholarship":"Academic Excellence - $5,000","status":"Active","payment_plan":"Semester Prepay","financial_aid_type":"Merit-Based","semester_charges":[{"semester":"Fall 2025","charged":9250,"paid":9250},{"semester":"Spring 2026","charged":9250,"paid":7250}]},
    {"person_id":"P008","type":"tuition","amount_due":18500,"amount_paid":13000,"balance":5500,"scholarship":"None","status":"Active","payment_plan":"Monthly Installment","financial_aid_type":"Self-Pay","semester_charges":[{"semester":"Fall 2025","charged":9250,"paid":9250},{"semester":"Spring 2026","charged":9250,"paid":3750}]},
    {"person_id":"P009","type":"salary","annual_salary":95000,"pay_frequency":"Biweekly","benefits":"Health + 401k","status":"Active","years_at_institution":8,"last_raise_date":"2025-07-01","last_raise_percent":3.5},
    {"person_id":"P010","type":"salary","annual_salary":82000,"pay_frequency":"Biweekly","benefits":"Health + 401k","status":"Active","years_at_institution":2,"last_raise_date":"2025-07-01","last_raise_percent":2.0},
    {"person_id":"P011","type":"salary","annual_salary":108000,"pay_frequency":"Biweekly","benefits":"Health + 401k + Housing","status":"Active","years_at_institution":15,"last_raise_date":"2025-07-01","last_raise_percent":4.0},
    {"person_id":"P014","type":"salary","annual_salary":98000,"pay_frequency":"Biweekly","benefits":"Health + 401k + Housing","status":"Active","years_at_institution":12,"last_raise_date":"2025-07-01","last_raise_percent":3.0},
    {"person_id":"P015","type":"salary","annual_salary":105000,"pay_frequency":"Biweekly","benefits":"Health + 401k","status":"Active","years_at_institution":5,"last_raise_date":"2025-07-01","last_raise_percent":4.5},
    {"person_id":"P012","type":"salary","annual_salary":145000,"pay_frequency":"Biweekly","benefits":"Executive Health + Pension","status":"Active","years_at_institution":20,"last_raise_date":"2025-07-01","last_raise_percent":2.5},
    {"person_id":"P013","type":"salary","annual_salary":78000,"pay_frequency":"Biweekly","benefits":"Health + 401k","status":"Active","years_at_institution":6,"last_raise_date":"2025-07-01","last_raise_percent":3.0}
  ],
  "grades": [
    {"student_id":"P001","class_id":"CS101","midterm":88,"final":91,"grade":"A-","attendance_rate":0.92,"assignment_avg":85,"lab_grade":"A","participation":"Active"},
    {"student_id":"P002","class_id":"CS101","midterm":95,"final":97,"grade":"A","attendance_rate":0.98,"assignment_avg":94,"lab_grade":"A+","participation":"Excellent"},
    {"student_id":"P003","class_id":"CS101","midterm":78,"final":82,"grade":"B","attendance_rate":0.85,"assignment_avg":80,"lab_grade":"B+","participation":"Active"},
    {"student_id":"P004","class_id":"CS101","midterm":70,"final":74,"grade":"C+","attendance_rate":0.75,"assignment_avg":68,"lab_grade":"C","participation":"Minimal"},
    {"student_id":"P005","class_id":"CS101","midterm":82,"final":86,"grade":"B+","attendance_rate":0.88,"assignment_avg":83,"lab_grade":"B+","participation":"Active"},
    {"student_id":"P008","class_id":"CS101","midterm":74,"final":78,"grade":"B-","attendance_rate":0.80,"assignment_avg":76,"lab_grade":"B-","participation":"Moderate"},
    {"student_id":"P003","class_id":"CS340","midterm":92,"final":95,"grade":"A","attendance_rate":0.96,"assignment_avg":93,"lab_grade":"A","participation":"Excellent"},
    {"student_id":"P005","class_id":"CS340","midterm":79,"final":83,"grade":"B","attendance_rate":0.86,"assignment_avg":81,"lab_grade":"B","participation":"Active"},
    {"student_id":"P007","class_id":"CS340","midterm":93,"final":91,"grade":"A","attendance_rate":0.95,"assignment_avg":90,"lab_grade":"A-","participation":"Excellent"},
    {"student_id":"P003","class_id":"CS450","midterm":88,"final":91,"grade":"A-","attendance_rate":0.94,"assignment_avg":89,"lab_grade":"A-","participation":"Active"},
    {"student_id":"P007","class_id":"CS450","midterm":97,"final":99,"grade":"A+","attendance_rate":1.00,"assignment_avg":98,"lab_grade":"A+","participation":"Outstanding"},
    {"student_id":"P001","class_id":"MATH201","midterm":72,"final":68,"grade":"C","attendance_rate":0.78,"assignment_avg":70,"lab_grade": None,"participation":"Moderate"},
    {"student_id":"P004","class_id":"MATH201","midterm":65,"final":58,"grade":"D","attendance_rate":0.62,"assignment_avg":55,"lab_grade": None,"participation":"Minimal"},
    {"student_id":"P006","class_id":"MATH201","midterm":84,"final":87,"grade":"B+","attendance_rate":0.90,"assignment_avg":82,"lab_grade": None,"participation":"Active"},
    {"student_id":"P008","class_id":"MATH201","midterm":86,"final":89,"grade":"B+","attendance_rate":0.91,"assignment_avg":84,"lab_grade": None,"participation":"Active"},
    {"student_id":"P002","class_id":"DS200","midterm":89,"final":92,"grade":"A-","attendance_rate":0.95,"assignment_avg":90,"lab_grade":"A","participation":"Excellent"},
    {"student_id":"P005","class_id":"DS200","midterm":90,"final":93,"grade":"A","attendance_rate":0.94,"assignment_avg":91,"lab_grade":"A","participation":"Active"},
    {"student_id":"P006","class_id":"DS200","midterm":76,"final":80,"grade":"B-","attendance_rate":0.82,"assignment_avg":78,"lab_grade":"B","participation":"Moderate"},
    {"student_id":"P007","class_id":"BUS201","midterm":85,"final":88,"grade":"B+","attendance_rate":0.90,"assignment_avg":86,"lab_grade": None,"participation":"Active"},
    {"student_id":"P008","class_id":"BUS201","midterm":78,"final":82,"grade":"B","attendance_rate":0.84,"assignment_avg":79,"lab_grade": None,"participation":"Moderate"},
    {"student_id":"P002","class_id":"DS350","midterm":91,"final":94,"grade":"A","attendance_rate":0.96,"assignment_avg":92,"lab_grade":"A","participation":"Excellent"},
    {"student_id":"P003","class_id":"DS350","midterm":87,"final":90,"grade":"A-","attendance_rate":0.93,"assignment_avg":88,"lab_grade":"A-","participation":"Active"}
  ],
  "classes": [
    {"class_id":"CS101","name":"Intro to Computer Science","teacher_id":"P009","teacher_name":"Sarah Chen","credits":3,"schedule":"MWF 9:00-9:50 AM","room":"Tech Hall 201","capacity":40,"enrolled_students":["P001","P002","P003","P004","P005","P008"],"class_average":82.9,"semester":"Spring 2026","prerequisites":[],"waitlist_count":3},
    {"class_id":"CS340","name":"Database Systems","teacher_id":"P009","teacher_name":"Sarah Chen","credits":3,"schedule":"TTh 1:00-2:15 PM","room":"Tech Hall 105","capacity":30,"enrolled_students":["P003","P005","P007"],"class_average":88.8,"semester":"Spring 2026","prerequisites":["CS101"],"waitlist_count":0},
    {"class_id":"CS450","name":"Machine Learning","teacher_id":"P010","teacher_name":"James Washington","credits":3,"schedule":"MWF 2:00-2:50 PM","room":"Tech Hall 301","capacity":20,"enrolled_students":["P003","P007"],"class_average":93.8,"semester":"Spring 2026","prerequisites":["CS101","MATH201"],"waitlist_count":5},
    {"class_id":"MATH201","name":"Calculus II","teacher_id":"P011","teacher_name":"Priya Sharma","credits":4,"schedule":"TTh 10:30-12:00 PM","room":"Science Bldg 305","capacity":35,"enrolled_students":["P001","P004","P006","P008"],"class_average":76.1,"semester":"Spring 2026","prerequisites":["MATH101"],"waitlist_count":0},
    {"class_id":"DS200","name":"Data Mining & Wrangling","teacher_id":"P010","teacher_name":"James Washington","credits":3,"schedule":"MWF 11:00-11:50 AM","room":"Analytics Lab 102","capacity":25,"enrolled_students":["P002","P005","P006"],"class_average":86.7,"semester":"Spring 2026","prerequisites":["CS101"],"waitlist_count":2},
    {"class_id":"BUS201","name":"Business Strategy & Analytics","teacher_id":"P014","teacher_name":"Michael Brooks","credits":3,"schedule":"TTh 3:00-4:15 PM","room":"Business Hall 200","capacity":30,"enrolled_students":["P007","P008"],"class_average":83.3,"semester":"Spring 2026","prerequisites":[],"waitlist_count":0},
    {"class_id":"DS350","name":"Advanced Data Analytics","teacher_id":"P015","teacher_name":"Elena Rodriguez","credits":3,"schedule":"MWF 1:00-1:50 PM","room":"Analytics Lab 201","capacity":20,"enrolled_students":["P002","P003"],"class_average":90.5,"semester":"Spring 2026","prerequisites":["DS200"],"waitlist_count":4}
  ],
  "departments": [
    {"dept_id":"CS","name":"Computer Science","head":"P009","faculty":["P009","P010"],"total_budget":283000,"num_faculty":2,"research_budget":65000,"ta_stipend_pool":24000,"operating_budget":194000,"grad_students":12,"adjunct_count":3},
    {"dept_id":"MATH","name":"Mathematics","head":"P011","faculty":["P011"],"total_budget":152000,"num_faculty":1,"research_budget":25000,"ta_stipend_pool":12000,"operating_budget":115000,"grad_students":6,"adjunct_count":2},
    {"dept_id":"BUS","name":"Business","head":"P014","faculty":["P014"],"total_budget":165000,"num_faculty":1,"research_budget":30000,"ta_stipend_pool":12000,"operating_budget":123000,"grad_students":4,"adjunct_count":1},
    {"dept_id":"DS","name":"Data Science","head":"P015","faculty":["P015"],"total_budget":178000,"num_faculty":1,"research_budget":45000,"ta_stipend_pool":15000,"operating_budget":118000,"grad_students":8,"adjunct_count":2}
  ],
  "academic_standing": [
    {"student_id":"P001","gpa":2.98,"credits_completed":42,"status":"Good Standing","deans_list": False,"academic_probation": False,"semester_gpas":[{"semester":"Fall 2024","gpa":3.20},{"semester":"Spring 2025","gpa":3.05},{"semester":"Fall 2025","gpa":2.70}],"academic_warnings":0,"honors_type": None},
    {"student_id":"P002","gpa":3.85,"credits_completed":78,"status":"Good Standing","deans_list": True,"academic_probation": False,"semester_gpas":[{"semester":"Fall 2023","gpa":3.70},{"semester":"Spring 2024","gpa":3.80},{"semester":"Fall 2024","gpa":3.90},{"semester":"Spring 2025","gpa":3.85},{"semester":"Fall 2025","gpa":3.95}],"academic_warnings":0,"honors_type":"Magna Cum Laude Track"},
    {"student_id":"P003","gpa":3.62,"credits_completed":105,"status":"Good Standing","deans_list": True,"academic_probation": False,"semester_gpas":[{"semester":"Fall 2022","gpa":3.40},{"semester":"Spring 2023","gpa":3.55},{"semester":"Fall 2023","gpa":3.60},{"semester":"Spring 2024","gpa":3.65},{"semester":"Fall 2024","gpa":3.70},{"semester":"Spring 2025","gpa":3.75},{"semester":"Fall 2025","gpa":3.62}],"academic_warnings":0,"honors_type":"Cum Laude Track"},
    {"student_id":"P004","gpa":1.65,"credits_completed":12,"status":"Academic Probation","deans_list": False,"academic_probation": True,"semester_gpas":[{"semester":"Spring 2026","gpa":1.65}],"academic_warnings":2,"honors_type": None},
    {"student_id":"P005","gpa":3.35,"credits_completed":72,"status":"Good Standing","deans_list": False,"academic_probation": False,"semester_gpas":[{"semester":"Fall 2023","gpa":3.10},{"semester":"Spring 2024","gpa":3.25},{"semester":"Fall 2024","gpa":3.40},{"semester":"Spring 2025","gpa":3.50},{"semester":"Fall 2025","gpa":3.35}],"academic_warnings":0,"honors_type": None},
    {"student_id":"P006","gpa":2.88,"credits_completed":38,"status":"Good Standing","deans_list": False,"academic_probation": False,"semester_gpas":[{"semester":"Fall 2024","gpa":2.95},{"semester":"Spring 2025","gpa":2.75},{"semester":"Fall 2025","gpa":2.90}],"academic_warnings":1,"honors_type": None},
    {"student_id":"P007","gpa":3.95,"credits_completed":110,"status":"Good Standing","deans_list": True,"academic_probation": False,"semester_gpas":[{"semester":"Fall 2022","gpa":3.90},{"semester":"Spring 2023","gpa":3.92},{"semester":"Fall 2023","gpa":3.95},{"semester":"Spring 2024","gpa":3.98},{"semester":"Fall 2024","gpa":3.95},{"semester":"Spring 2025","gpa":3.97},{"semester":"Fall 2025","gpa":3.95}],"academic_warnings":0,"honors_type":"Summa Cum Laude Track"},
    {"student_id":"P008","gpa":2.72,"credits_completed":65,"status":"Good Standing","deans_list": False,"academic_probation": False,"semester_gpas":[{"semester":"Fall 2023","gpa":2.60},{"semester":"Spring 2024","gpa":2.55},{"semester":"Fall 2024","gpa":2.80},{"semester":"Spring 2025","gpa":2.85},{"semester":"Fall 2025","gpa":2.72}],"academic_warnings":1,"honors_type": None}
  ],
  "advisor_assignments": [
    {"advisor_id":"P009","student_id":"P001","assigned_date":"2024-08-20","department":"Computer Science","meeting_frequency":"Biweekly","last_meeting":"2026-03-15","notes":"Discussing grad school options. GPA trending down."},
    {"advisor_id":"P015","student_id":"P002","assigned_date":"2023-08-18","department":"Data Science","meeting_frequency":"Monthly","last_meeting":"2026-03-10","notes":"Strong candidate for honors thesis."},
    {"advisor_id":"P009","student_id":"P003","assigned_date":"2022-08-22","department":"Computer Science","meeting_frequency":"Monthly","last_meeting":"2026-03-20","notes":"Senior capstone in progress. TA duties going well."},
    {"advisor_id":"P011","student_id":"P004","assigned_date":"2026-01-10","department":"Mathematics","meeting_frequency":"Weekly","last_meeting":"2026-03-25","notes":"URGENT: Academic probation. Financial hold. Considering reduced course load."},
    {"advisor_id":"P011","student_id":"P005","assigned_date":"2023-08-18","department":"Mathematics","meeting_frequency":"Biweekly","last_meeting":"2026-03-18","notes":"Cross-department advising for math minor."},
    {"advisor_id":"P015","student_id":"P006","assigned_date":"2024-08-20","department":"Data Science","meeting_frequency":"Monthly","last_meeting":"2026-03-12","notes":"Exploring data science specializations."},
    {"advisor_id":"P009","student_id":"P007","assigned_date":"2022-08-22","department":"Computer Science","meeting_frequency":"Monthly","last_meeting":"2026-03-08","notes":"Top performer. Cross-enrolled in Business for minor."},
    {"advisor_id":"P011","student_id":"P008","assigned_date":"2023-08-18","department":"Mathematics","meeting_frequency":"Biweekly","last_meeting":"2026-03-22","notes":"Solid performance. Interested in actuarial science."}
  ],
  "ta_assignments": [
    {"ta_id":"TA001","student_id":"P003","class_id":"CS101","semester":"Spring 2026","stipend":6000,"hours_per_week":10,"supervising_faculty":"P009","performance_rating":"Excellent","duties":["Grading","Office Hours","Lab Supervision"]},
    {"ta_id":"TA002","student_id":"P003","class_id":"DS200","semester":"Spring 2026","stipend":4000,"hours_per_week":6,"supervising_faculty":"P010","performance_rating":"Good","duties":["Grading","Tutorial Sessions"]},
    {"ta_id":"TA003","student_id":"P007","class_id":"CS340","semester":"Spring 2026","stipend":6000,"hours_per_week":10,"supervising_faculty":"P009","performance_rating":"Outstanding","duties":["Grading","Office Hours","Project Mentoring"]}
  ]
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()
    data = generate()
    out = args.output or str(Path(__file__).parent / "demo_university.json")
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    s = sum(1 for p in data["persons"] if p["role"]=="Student")
    t = sum(1 for p in data["persons"] if p["role"]=="Teacher")
    a = sum(1 for p in data["persons"] if p["role"]=="Admin")
    print(f"Generated: {len(data['persons'])} people ({s} students, {t} faculty, {a} admin)")
    print(f"Grades: {len(data['grades'])} | Classes: {len(data['classes'])} | Depts: {len(data['departments'])}")
    print(f"Standing: {len(data['academic_standing'])} | Advisors: {len(data['advisor_assignments'])} | TAs: {len(data['ta_assignments'])}")
    print(f"Edge cases: P003=dual TA, P004=probation+delinquent, P005=cross-dept advisor, P007=cross-dept enrollment")
    for d in data["departments"]:
        sal = sum(f["annual_salary"] for f in data["financial_information"] if f["person_id"] in d["faculty"])
        print(f"  IC-001 {d['name']}: budget=${d['total_budget']:,} salaries=${sal:,}")
    print(f"Written to: {out} ({Path(out).stat().st_size:,} bytes)")

if __name__ == "__main__":
    main()