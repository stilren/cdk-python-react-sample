import React from 'react';
import ReactDOM from 'react-dom';
import { Amplify } from 'aws-amplify';
import { BrowserRouter as Router } from 'react-router-dom';
import './index.css';
import App from './App';
import outputs from './outputs';
import { initSentry } from './libs/errorLib';
import * as serviceWorker from './serviceWorker';
import { Auth } from "aws-amplify";

initSentry();

Amplify.configure({
  Auth: {
    mandatorySignIn: true,
    region: outputs.backend.REGION,
    userPoolId: outputs.backend.USERPOOLID,
    identityPoolId: outputs.backend.IDENTITYPOOLID,
    userPoolWebClientId: outputs.backend.APPCLIENTID
  },
  API: {
    endpoints: [
      {
        name: "notes",
        endpoint: `${outputs.backend.GATEWAYURL}note` ,
        region: outputs.backend.REGION,
        custom_header: async () => { 
          return { Authorization: `Bearer ${(await Auth.currentSession()).getAccessToken().getJwtToken()}` }
        }
      },
    ]
  }
});

ReactDOM.render(
  <Router>
    <App />
  </Router>,
  document.getElementById('root')
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
