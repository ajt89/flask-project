import React from 'react';
import '../styles/home-page.css';
import { connect } from 'react-redux';
import { validateUser } from '../actions/loginActions';

class HomePage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      username: '',
      password: '',
    };
  }

  handleUsernameChange(event) {
    this.setState({username: event.target.value});
  }

  handlePasswordChange(event) {
    this.setState({password: event.target.value});
  }

  render() {
    return (
      <div className="login">
        <h2 className="login-header">Log in</h2>
        <form className="login-container">
          <p><input type="username" placeholder="Username" value={this.state.username} onChange={this.handleUsernameChange}/></p>
          <p><input type="password" placeholder="Password" value={this.state.password} onChange={this.handlePasswordChange}/></p>
          <p><input type="submit" value="Log in"/></p>
        </form>
      </div>
    );
  }
}

function mapDispatchToProps(dispatch) {
  return {
    handleSubmit: (username, password) => {
      dispatch(validateUser(username, password));
    }
  };
}

// function mapDispatchToProps(dispatch) {
//   return {
//     loadUserFromToken: () => {
//       const token = sessionStorage.getItem('jwtToken');
//       if (!token || token === '') { // if there is no token don't bother
//         return;
//       }
//       dispatch(fetchUserFromToken(token));
//     },
//     logout: () => {
//       sessionStorage.removeItem('jwtToken'); // remove token from storage
//       dispatch(resetToken());
//     },
//   };
// }

export default connect(mapDispatchToProps)(HomePage);
