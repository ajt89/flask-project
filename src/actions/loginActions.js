import * as types from '../constants/actionTypes';

export function validateUser(username, password) {
  return {
    type: types.VALIDATE_USER_LOGIN,
    username,
    password,
  };
}
