import { initializeApp } from "firebase/app";

function initFirebase() {
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
}

export default initFirebase
