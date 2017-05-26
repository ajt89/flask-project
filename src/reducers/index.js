import { combineReducers } from 'redux';
import {routerReducer} from 'react-router-redux';
import loginReducer from './loginReducer';

const rootReducer = combineReducers({
  login: loginReducer,
  routing: routerReducer
});

export default rootReducer;
