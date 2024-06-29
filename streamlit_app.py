import streamlit as st
import requests
import pandas as pd

st.set_page_config(layout='wide')

BASE_URL = 'http://127.0.0.1:5000'

def login(username, password):
    response = requests.post(f'{BASE_URL}/login', json={'username': username, 'password': password})
    if response.status_code == 200:
        st.session_state['logged_in'] = True
        st.session_state['cookie'] = response.cookies.get_dict()
        st.session_state['role'] = response.json()['role']
    return response.json()

def register(username, password, role):
    response = requests.post(f'{BASE_URL}/register', json={'username': username, 'password': password, 'role': role.lower()})
    return response.json()

def submit_grievance(grievance_type, description, department, severity):
    if 'cookie' in st.session_state:
        response = requests.post(f'{BASE_URL}/grievance', json={
            'grievance_type': grievance_type,
            'description': description,
            'department': department,
            'severity': severity
        }, cookies=st.session_state['cookie'])
        return response.json()
    else:
        return {'message': 'You must be logged in to submit a grievance'}

def view_grievances():
    if 'cookie' in st.session_state:
        response = requests.get(f'{BASE_URL}/grievances', cookies=st.session_state['cookie'])
        grievances = response.json()
        df = pd.DataFrame(grievances)
        return grievances, df
    else:
        return [], pd.DataFrame()

def update_grievance_status(grievance_id, status):
    if 'cookie' in st.session_state:
        response = requests.put(f'{BASE_URL}/grievance/{grievance_id}', json={'status': status}, cookies=st.session_state['cookie'])
        return response.json()
    else:
        return {'message': 'You must be logged in to update grievance status'}

st.header(':red[Organizational Grievance Support System]', divider='rainbow')

menu = ['Login', 'Register', 'Submit Grievance', 'View Grievances']
if 'role' in st.session_state and st.session_state['role'] == 'admin':
    menu.append('Admin Dashboard')

with st.sidebar:
    choice = st.selectbox("Main Menu", menu, index=0)

if choice == 'Login':
    st.subheader('Login')
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    if st.button('Login'):
        result = login(username, password)
        st.write(result)

elif choice == 'Register':
    st.subheader('Register')
    username = st.text_input('Username')
    password = st.text_input('Password', type='password')
    role = st.selectbox('Role', ['Employee', 'HR', 'IT', 'Admin'])
    if st.button('Register'):
        result = register(username, password, role)
        st.write(result)

elif choice == 'Submit Grievance':
    if 'logged_in' in st.session_state and st.session_state['logged_in']:
        st.subheader('Submit Grievance')
        grievance_type = st.selectbox('Grievance Type', ['Type 1', 'Type 2', 'Type 3'])
        description = st.text_area('Description')
        if st.session_state['role'] == 'Employee':
            department = st.selectbox('Department', ['HR', 'IT'])
        else:
            department = st.selectbox('Department', ['HR', 'IT', 'Department 1', 'Department 2', 'Department 3'])
        severity = st.selectbox('Severity', ['Low', 'Medium', 'High'])
        if st.button('Submit'):
            result = submit_grievance(grievance_type, description, department, severity)
            st.write(result)
    else:
        st.write("You must be logged in to submit a grievance.")

elif choice == 'View Grievances':
    if 'logged_in' in st.session_state and st.session_state['logged_in']:
        grievances, df = view_grievances()
        if st.session_state['role'] == 'HR' or st.session_state['role'] == 'IT':
            for grievance in grievances:
                st.write(grievance)
                new_status = st.selectbox(f"Change status for grievance {grievance['id']}", ['Pending', 'Completed'], index=['Pending', 'Completed'].index(grievance['status']))
                if st.button(f"Update status for grievance {grievance['id']}"):
                    result = update_grievance_status(grievance['id'], new_status)
                    st.write(result)
        else:
            st.table(df)
    else:
        st.write("You must be logged in to view grievances.")

elif choice == 'Admin Dashboard':
    if 'logged_in' in st.session_state and st.session_state['logged_in'] and st.session_state['role'] == 'admin':
        grievances, df = view_grievances()
        pending = sum(1 for g in grievances if g['status'] == 'Pending')
        completed = sum(1 for g in grievances if g['status'] == 'Completed')
        total = len(grievances)

        cols = st.columns(3)
        with cols[0]:
            st.metric("Total grievances", total, "+20.1% from last month")
        with cols[1]:
            st.metric("Pending grievances", pending, "+20.1% from last month")
        with cols[2]:
            st.metric("Completed grievances", completed, "+20.1% from last month")
        
        st.table(df)    
            
    else:
        st.write("You must be logged in as admin to view the dashboard.")
