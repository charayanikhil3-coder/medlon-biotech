import {initializeApp} from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js';
import {getAuth,signInWithEmailAndPassword,onAuthStateChanged,signOut,getIdToken} from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js';

// Firebase web config is public by design. NEVER put Admin UID or passwords in this file.
const firebaseConfig={
  apiKey:'AIzaSyCcyi4y82mxgaS8_ITtT6bM9AXALB5aflA',
  authDomain:'medlon-biotech-admin.firebaseapp.com',
  projectId:'medlon-biotech-admin',
  appId:'1:1048929043069:web:218b08165166837e582714'
};
const firebaseApp=initializeApp(firebaseConfig);
const auth=getAuth(firebaseApp);
const gate=document.querySelector('#loginGate');
const shell=document.querySelector('#adminShell');
const form=document.querySelector('#loginForm');
const message=document.querySelector('#authMessage');
const submit=document.querySelector('#loginBtn');
let loaded=false;
const display=(s)=>{message.textContent=s;};
const showGate=()=>{shell.classList.remove('is-authorized');gate.hidden=false;loaded=false;};
window.MedlonAuth={
 token: async()=>auth.currentUser?getIdToken(auth.currentUser):null,
 logout:()=>signOut(auth)
};
async function checkAdmin(u){
  const t=await getIdToken(u);
  const r=await fetch('/admin/api/orders',{headers:{Authorization:`Bearer ${t}`},cache:'no-store'});
  if(r.status===401||r.status===403){showGate();display('This account is not authorized as Medlon Admin. Check ADMIN_UID in Cloudflare settings.');return;}
  if(!r.ok){showGate();display('Admin server is not ready ('+r.status+'). Check deployment and database binding.');return;}
  gate.hidden=true;shell.classList.add('is-authorized');display('');
  if(!loaded){loaded=true;window.MedlonDashboardStart?.();}
}
form.addEventListener('submit',async(e)=>{
  e.preventDefault();submit.disabled=true;display('Verifying your account…');
  try{
    const email=document.querySelector('#adminEmail').value.trim();
    const password=document.querySelector('#adminPassword').value;
    await signInWithEmailAndPassword(auth,email,password);
    document.querySelector('#adminPassword').value='';
  }catch(e){display('Login failed. Verify your email and password, then try again.');}
  finally{submit.disabled=false;}
});
document.querySelector('#logoutBtn').addEventListener('click',async()=>{
  try{await signOut(auth);showGate();display('You have signed out.');}catch{display('Could not sign out. Please retry.');}
});
onAuthStateChanged(auth,(u)=>{
  if(!u){showGate();display('Sign in to access the Medlon Admin dashboard.');return;}
  display('Checking administrator permissions…');
  checkAdmin(u).catch(()=>{showGate();display('Unable to verify admin login. Check connection and try again.');});
},()=>{showGate();display('Firebase Authentication unavailable. Check your connection.');});
