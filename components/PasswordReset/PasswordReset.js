import React, { Component } from 'react';
import PropTypes from 'prop-types';
import Router from 'next/router';
import { graphql } from '@apollo/client/react/hoc';
import compose from 'lodash.flowright';
import { gql } from '@apollo/client';
import { withFormik } from 'formik';
import { Form, Button } from 'semantic-ui-react';
import { validate } from 'lib/form';
import { CURRENT_USER_QUERY } from '../User/User';
import Error from '../errors/ApolloError';
import { getValidationSchema } from './validationSchema';
import './PasswordReset.scss';

const UPDATE_PASSWORD_MUTATION = gql`
  mutation UPDATE_PASSWORD_MUTATION($tempToken: String!, $password: String!, $confirmPassword: String!) {
    updatePassword(tempToken: $tempToken, password: $password, confirmPassword: $confirmPassword) {
      id
    }
  }
`;

class PasswordReset extends Component {
  render() {
    const {
      errors,
      values,
      handleChange,
      handleSubmit,
      isSubmitting,
    } = this.props;

    return (
      <div className="reset reset_wrapper">
        <h1 className="reset_title">Reset Password</h1>
        <p className="reset_subtext">Update your password.</p>
        <p className="helperText">Passwords must be a minimum of 8 characters long and contain at least one uppercase letter (A-Z), one lowercase letter (a-z), one number (0-9), and one special character (`~!@#$%^&amp;*.\&lt;&gt;"/\',()_-+=[]|\\).</p>
        <Error error={ errors.submit } />
        <Form
          noValidate
          onSubmit={ handleSubmit }
        >
          <Form.Field>
            <Form.Input
              id="password"
              label="Password"
              name="password"
              type="password"
              value={ values.password }
              onChange={ handleChange }
              error={ !!errors.password }
              required
            />
            <p className="error-message">{ errors.password }</p>
          </Form.Field>
          <Form.Field>
            <Form.Input
              id="confirmPassword"
              label="Confirm Password"
              name="confirmPassword"
              type="password"
              value={ values.confirmPassword }
              onChange={ handleChange }
              error={ !!errors.confirmPassword }
              required
            />
            <p className="error-message">{ errors.confirmPassword }</p>
          </Form.Field>
          <Button
            type="submit"
            loading={ isSubmitting }
            disabled={ isSubmitting }
            className="primary"
          >
            Reset Password
          </Button>
        </Form>
      </div>
    );
  }
}

PasswordReset.propTypes = {
  values: PropTypes.object,
  errors: PropTypes.object,
  handleSubmit: PropTypes.func,
  handleChange: PropTypes.func,
  isSubmitting: PropTypes.bool,
};


export default compose(
  graphql( UPDATE_PASSWORD_MUTATION ),
  withFormik( {
    mapPropsToValues: () => ( {
      password: '',
      confirmPassword: '',
    } ),

    validate: validate( getValidationSchema ),
    validateOnBlur: false,
    validateOnChange: false,

    handleSubmit: async ( values, { props: { mutate, tempToken }, setErrors, setSubmitting } ) => {
      try {
        await mutate( {
          variables: {
            tempToken,
            password: values.password,
            confirmPassword: values.confirmPassword,
          },
          refetchQueries: [{ query: CURRENT_USER_QUERY }],
        } );

        // if password reset is successful, send user to dashboard
        Router.push( '/' );
      } catch ( err ) {
        setErrors( {
          submit: err,
        } );
      }
      setSubmitting( false );
    },
  } ),
)( PasswordReset );
