import {
  VALIDATE_USER_LOGIN,
  VALIDATE_USER_LOGIN_SUCCESS,
  VALIDATE_USER_LOGIN_FAILURE,
} from '../constants/actionTypes';
import { fromJS } from 'immutable';

// The initial state of the App
const initialState = fromJS({
  loading: false,
  error: false,
  currentUser: false,
});

function loginReducer(state = initialState, action) {
  switch (action.type) {
    case VALIDATE_USER_LOGIN:
      return state;
    case VALIDATE_USER_LOGIN_SUCCESS:
      return state;
    case VALIDATE_USER_LOGIN_FAILURE:
      return state;
    default:
      return state;
  }
}

export default loginReducer;
