import React, {PropTypes} from 'react';

class Dashboard extends React.Component {
  constructor(props, context) {
    super(props, context);
  }

  render() {
    return (
      <div>
        <h2>Fuel Savings Analysis</h2>
        <table>
          <tbody>
          <tr>
            <td><label htmlFor="newMpg">New Vehicle MPG</label></td>
          </tr>
          <tr>
            <td><label htmlFor="tradeMpg">Trade-in MPG</label></td>
          </tr>
          <tr>
            <td><label htmlFor="newPpg">New Vehicle price per gallon</label></td>
          </tr>
          <tr>
            <td><label htmlFor="tradePpg">Trade-in price per gallon</label></td>
          </tr>
          <tr>
            <td><label htmlFor="milesDriven">Miles Driven</label></td>
          </tr>
          <tr>
            <td><label>Date Modified</label></td>
          </tr>
          </tbody>
        </table>

        <hr/>
      </div>
    );
  }
}

Dashboard.propTypes = {
};

export default Dashboard;
