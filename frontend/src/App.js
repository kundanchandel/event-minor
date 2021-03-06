import React from 'react';
import './App.css';
import '../node_modules/bootstrap/dist/css/bootstrap.min.css';
import NavBar from './components/Header/NavBar';
import {BrowserRouter,Route} from 'react-router-dom';
import Landing from './components/Landing/Landing';
import CreateEvent from './components/CreateEvent';
import Login from './components/Login';
import BrowseEvent from './components/BrowseEvent'; 
import {Provider} from 'react-redux';
import store from './store';

function App() {
  return (
    
    <BrowserRouter>
    <Provider store={store}>
    <div className="App" >
      <NavBar />
     <Route exact path="/" component={Landing} />
     <Route exact path="/create" component={CreateEvent}/>
     <Route exact path="/login" component={Login} />
     <Route exact path='/browseevent' component={BrowseEvent} />
    </div>
    </Provider>
    </BrowserRouter>
    
  );
}

export default App;
