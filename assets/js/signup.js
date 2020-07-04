'use strict';
import styles from './../css/signup.css';
import image from './../admin-tool.png';
const m = require("mithril");

const root = document.body;

function main() {
    
  m.render(root, m("div.formcontainer",
  [
        m("label","Signup to Site"),
        m("div.loginform",
        [
            m("label[for='name']","Name"),
            m("br"),
            m("input#name.forminput[type=text][name='name']"),
            m("br"),
            m("label[for='email']","Email"),
            m("br"),
            m("input#email.forminput[type=email][name='email']"),
            m("br"),
            m("label[for='pwd']","Password"),
            m("br"),
            m("input#pwd.forminput[type=password][name='pwd']"),
            m("br"),
            m("button#signup.text-center.button",{
              onclick() {
                m.request({
                  method: "POST",
                  url: "/api/signup",
                  body: {
                    name: document.getElementById('name').value ,
                    email: document.getElementById('email').value ,
                    password: document.getElementById('pwd').value ,
                  }
              })
              .then(function(result) {
                if(result== null){
                  console.log('failed');
                }else{
                  if(result.redirect == 'true'){
                  window.location.href = result.redirectlink;
                  }
                  console.log(result);
                }
              })
              }
          },"Signup"),
        ]),
  ]
  ));
}

window.onload = main;