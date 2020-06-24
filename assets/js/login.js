'use strict';
import styles from './../css/login.css';
import image from './../admin-tool.png';
const m = require("mithril");

const root = document.body;

function main() {
    
  m.render(root, m("div.formcontainer",
  [
        m("label","Login to Site"),
        m("br"),
        m("div.loginform",
        [
            m("label[for='name']","Name"),
            m("br"),
            m("input#name.forminput[type=text][name='name']"),
            m("br"),
            m("label[for='pwd']","Password"),
            m("br"),
            m("input#pwd.forminput[type=password][name='pwd']"),
            m("br"),
            m("button.button",{
              onclick() {
                m.request({
                  method: "POST",
                  url: "/api/login",
                  body: {
                    name: document.getElementById('name').value ,
                    password: document.getElementById('pwd').value ,
                  }
              })
              .then(function(result) {
                if(result== null){
                  console.log('failed');
                }else{
                  window.location.href = result.redirecturl;
                  console.log(result);
                }
              })
              }
            },"Login"),
        ]),
  ]
  ));
}

window.onload = main;