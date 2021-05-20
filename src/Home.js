import { AuthenticationDetails, CognitoUser, CognitoUserPool } from 'amazon-cognito-identity-js'
import { v4 as uuidv4 } from 'uuid';

import React, { Component } from 'react';
import { Button, Form } from 'react-bootstrap';

const clientId = 'X';
const poolName = 'X'
const userPool = new CognitoUserPool({
    UserPoolId: 'X',
    ClientId: clientId
});

// from: https://github.com/aaronpk/pkce-vanilla-js/blob/master/index.html
function sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest('SHA-256', data);
}


async function pkceChallengeFromVerifier(v) {
    var hashed = await sha256(v);
    return base64urlencode(hashed);
}

function base64urlencode(str) {

    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}



class Home extends Component {

    constructor(props) {
        super(props)

        this.state = {
            "jwt": ""
        }
        this.handleSubmit = this.handleSubmit.bind(this);
        this.toCognito = this.toCognito.bind(this);
        this.handleUpdate = this.handleUpdate.bind(this);

    }

    toCognito() {
        var state = uuidv4();
        localStorage.setItem('state', state)
        var codeVerfiier = uuidv4();
        localStorage.setItem('codeVerifier', codeVerfiier)
        var codeChallenge = pkceChallengeFromVerifier(codeVerfiier).then(cv => {
            const url = `https://${poolName}.auth.eu-west-1.amazoncognito.com/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=http://localhost:3000&scope=openid&state=${state}&code_challenge_method=S256&code_challenge=${cv}`
            window.location.assign(url)
        })
    }

    

    componentDidMount() {
        if (this.state.jwt) {
            return;
        }
        console.log(window.location.search)
        var paramsString = new URLSearchParams(window.location.search)
        var code = paramsString.get("code")
        if (code == null) {
            this.toCognito();
        }
        var storedState = localStorage.getItem('state')
        var receivedState = paramsString.get("state")
        var storedCodeVerifier = localStorage.getItem("codeVerifier")
    
        console.log(code);
        if (code != null) {
            if (receivedState !== storedState) {
                alert('corrupt state');
            }
            var self = this
            const url = `https://ala-test.auth.eu-west-1.amazoncognito.com/oauth2/token`
            const postData = new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: clientId,
                redirect_uri: 'http://localhost:3000',
                code: code,
                code_verifier: storedCodeVerifier
            })

            fetch(url, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: postData
            }
            )
            .then(response => response.json())
            .then(result => {
                console.log(result)
                self.setState({ 'jwt' : result.id_token })
            });
        }
    }

    handleUpdate(event) {
        this.setState({[event.target.id] : event.target.value });    
    }

    handleSubmit(event) {
        event.preventDefault();
        console.log(this.state.username);
        console.log(userPool);
        var cognitoUser = new CognitoUser({
            Username: this.state.formUserName,
            Pool: userPool
        });
        var authenticationDetails = new AuthenticationDetails({
            Username: this.state.formUserName,
            Password: this.state.formPassword
        });
        const self = this;
        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: function(result) {
                console.log("token : " + result.getIdToken().getJwtToken());
                self.setState({'jwt' : result.getIdToken().getJwtToken() });
            },
            onFailure: function(err) {
                console.log(err.message || JSON.stringify(err))
            }
        })

    }

    render() {
        if (this.state.jwt) {
            return ( <div>{this.state.jwt}</div> );
        }
        return (
            <div>
                <Button variant="primary" onClick={this.toCognito}>Login with username password</Button>
                <Form onSubmit={this.handleSubmit}>
                    <Form.Group controlId="formUserName">
                        <Form.Label>Username</Form.Label>
                        <Form.Control value={this.state.username} onChange={this.handleUpdate}></Form.Control>
                    </Form.Group>
                    <Form.Group controlId="formPassword">
                        <Form.Label>Password</Form.Label>
                        <Form.Control type="password" value={this.state.password} onChange={this.handleUpdate}></Form.Control>
                    </Form.Group>
                    <Button type="submit">Login</Button>
                </Form>
                </div>
        )
    }
}

export default Home;