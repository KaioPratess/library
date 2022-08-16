import { initializeApp } from "firebase/app";
import { getStorage, ref } from "firebase/storage";
import { getAuth, signInWithPopup, GoogleAuthProvider } from 'firebase/auth';
import { collection, addDoc, getFirestore, getDocs} from "firebase/firestore";

function initFirebase() {
  const loginBtn = document.querySelector('.login');
  const profile = document.querySelector('.profile');
  const pic = document.querySelector('.profile img');
  const name = document.querySelector('.profile p');
  const inputs = document.querySelectorAll("[data-key]");
  const saveBtn = document.querySelector(".btn");
  
    // Import the functions you need from the SDKs you need
  // TODO: Add SDKs for Firebase products that you want to use
  // https://firebase.google.com/docs/web/setup#available-libraries

  // Your web app's Firebase configuration
  const firebaseConfig = {
    apiKey: "AIzaSyD4hRhZgzrKfedzhSos5i9exPce6nC1R_w",
    authDomain: "library-fa401.firebaseapp.com",
    projectId: "library-fa401",
    storageBucket: "library-fa401.appspot.com",
    messagingSenderId: "824732299942",
    appId: "1:824732299942:web:bcb35f795f51b7ca7afa67"
  };

  // Initialize Firebase
  const app = initializeApp(firebaseConfig);

  // Initialize Cloud Storage and get a reference to the service
  const storage = getStorage(app);
  const storageRef = ref(storage);

  // Initialize Cloud Firestore and get a reference to the service
  const db = getFirestore(app);

 async function addToDb() {
  let filled = false;
  let properties = [];

  inputs.forEach(input => {
    if(input.value) {
      filled = true;
      properties.push(input.value)
    } else {
      filled = false;
    }
  }) 

  if(filled) {
      try {
      const docRef = await addDoc(collection(db, "books"), {
        title: properties[0],
        author: properties[1],
        pages: properties[2],
        releaseYear: properties[3],
      });
      console.log("Document written with ID: ", docRef.id);
    } catch (e) {
      console.error("Error adding document: ", e);
    }
  };

  };

  // Initialize Authentication
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({
    'login_hint': 'user@example.com'
  });
  provider.addScope('https://www.googleapis.com/auth/contacts.readonly');

  const auth = getAuth();
  auth.languageCode = 'it';

  function signIn() {
    signInWithPopup(auth, provider)
    .then((result) => {
      // This gives you a Google Access Token. You can use it to access the Google API.
      const credential = GoogleAuthProvider.credentialFromResult(result);
      const token = credential.accessToken;
      // The signed-in user info.
      const user = result.user;
      console.log(user)
      pic.setAttribute('src', user.photoURL);
      name.textContent = user.displayName;
      loginBtn.style.display = 'none';
      profile.style.display = 'flex';
      // ...
    }).catch((error) => {
      // Handle Errors here.
      const errorCode = error.code;
      const errorMessage = error.message;
      // The email of the user's account used.
      const email = error.customData.email;
      // The AuthCredential type that was used.
      const credential = GoogleAuthProvider.credentialFromError(error);
      // ...
    });


  }



  loginBtn.addEventListener('click', signIn);
  saveBtn.addEventListener('click', addToDb)
}

export default initFirebase
