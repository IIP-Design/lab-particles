import { ApolloError, AuthenticationError, UserInputError } from 'apollo-server-express';
import { confirmationEmail, passwordResetEmail } from '../../services/mailTemplates';

const COOKIE_MAX_AGE = 1000 * 60 * 60 * 24 * 7; // 1 week, matches CloudFlare maxAge

const setCookie = ( ctx, jwtToken ) => {
  ctx.res.cookie( 'americaCommonsToken', jwtToken, {
    httpOnly: true, // only allow access to cookie from the server
    maxAge: COOKIE_MAX_AGE,
    secure: !process.env.NODE_ENV === 'development',
    sameSite: 'Lax',
  } );
};

/**
 * Sign user in via email/password
 *
 * @param {object} args { email, password }
 */
 async signIn( parent, { email, password }, ctx ) {
  // 1. check if there is a user with that email
  const user = await ctx.prisma.user( { email } );

  if ( !user && email.includes( 'america.gov' ) ) {
    throw new AuthenticationError(
      'You must first register your account before you can sign in.',
    );
  }

  if ( !user ) {
    throw new AuthenticationError(
      'You must first register using your america.gov email account to sign in.',
    );
  }

  if ( ENFORCE_WHITELIST ) {
    const whitelisted = await isEmailWhitelisted( email );

    if ( !whitelisted ) {
      throw new AuthenticationError(
        'This america.gov account is not currently approved during our beta testing period.',
      );
    }
  }

  if ( !user.isConfirmed ) {
    throw new AuthenticationError( 'You must confirm your account before you can sign in.' );
  }

  // 2. Check if their password is correct
  const valid = await bcrypt.compare( password, user.password );

  if ( !valid ) {
    throw new AuthenticationError( 'Invalid Password!' );
  }

  // 3. generate the JWT Token
  const jwtToken = await generateToken( user.id );

  // 4. Set the cookie with the token
  setCookie( ctx, jwtToken );

  // 5. Return the user
  return user;
},

/**
 * Creates an unconfirmed user in db then send confirmation email
 *
 * @param {object} args { UserCreateInput }
 */
async signUp( parent, args, ctx ) {
  if ( ENFORCE_WHITELIST ) {
    const whitelisted = await isEmailWhitelisted( args.data.email );

    if ( !whitelisted ) {
      throw new UserInputError(
        'This america.gov account is not currently approved during our beta testing period.',
      );
    }
  }
  try {
    // 1. Set a temporary token and expiry on that user for confirmation purposes
    const { tempToken, tempTokenExpiry } = await createToken();
    const userWithToken = { ...args.data, tempToken, tempTokenExpiry };

    // 1a. Until more permissions are enabled, force to editor
    const userWithTokenEditorOnly = userWithToken;

    userWithTokenEditorOnly.permissions.set = ['EDITOR'];

    // 2. Create an unconfirmed user in the db
    const user = await ctx.prisma
      .createUser( userWithTokenEditorOnly )
      .$fragment( 'fragment UserSignUp on User { id email team { name } }' );

    // 3. Email the user
    if ( user ) {
      const { team } = user;
      const confirmLink = `${process.env.FRONTEND_URL}/confirm?tempToken=${tempToken}`;
      const body = confirmationEmail( confirmLink, team.name );
      const subject = 'Complete your registration';
      const params = setSesParams( user.email, body, subject );

      await sendSesEmail( params );
    }

    return {
      text: 'Please check your email for a link to confirm your registration',
    };
  } catch ( err ) {
    throw new ApolloError( 'There is already a user with that email in the system.' );
  }
},

/**
 * Verify temporary token is still valid, and passwords match
 * If so, update isConfirmed user property and store password
 * Then create a token, set cookie and return user
 *
 * This is should for both registration confirmation and password resets
 *
 * @param {object} args
 */
async updatePassword( parent, args, ctx ) {
  // 1. Verify passwords match.  This is a second check as it is checked in client
  if ( args.password !== args.confirmPassword ) {
    throw new AuthenticationError( "Your Passwords don't match!" );
  }
  // 2. check if its a legit reset token
  // 3. Check if its expired
  const [user] = await ctx.prisma.users( {
    where: {
      tempToken: args.tempToken,
      tempTokenExpiry_gte: Date.now() - 3600000,
    },
  } );

  if ( !user ) {
    throw new AuthenticationError( 'This token is either invalid or expired!' );
  }

  // 4. Hash their new password
  const password = await bcrypt.hash( args.password, 10 );

  // 5. Save the new password to the user and remove old tempToken fields
  const updatedUser = await ctx.prisma.updateUser( {
    where: { email: user.email },
    data: {
      password,
      isConfirmed: true,
      tempToken: null,
      tempTokenExpiry: null,
    },
  } );

  // 6. Generate JWT
  const jwtToken = await ( user.id );

  // 7. Set the JWT cookie
  setCookie( ctx, jwtToken );

  // 8. return the new user
  return updatedUser;
},

/**
 * Checks for valid user and send email with token to execute action
 *
 * @param {object} args { UserCreateInput }
 */
async requestAccountAction( parent, args, ctx ) {
  const { email, subject, body, link, reply, page } = args;

  try {
    // 1. check if there is a user with that email and if they are confirmed.
    const user = await ctx.prisma
      .user( { email } )
      .$fragment( 'fragment UserAccountAction on User { id email team { name } isConfirmed }' );

    if ( !user ) {
      throw new AuthenticationError( `No user found for email ${email}` );
    }

    if ( page === 'passwordreset' && !user.isConfirmed ) {
      throw new AuthenticationError(
        'You must confirm your account before you can reset your password.',
      );
    }

    if ( page === 'confirm' && user.isConfirmed ) {
      throw new AuthenticationError( 'Your account has already been confirmed!' );
    }

    // 2. Set a temporary token and expiry on that user for confirmation purposes
    const { tempToken, tempTokenExpiry } = await createToken();
    const userWithToken = { tempToken, tempTokenExpiry };

    // 3. Update user with temporary token
    const updatedUser = await ctx.prisma.updateUser( {
      data: userWithToken,
      where: {
        email,
      },
    } );

    // 4. Email the user
    if ( updatedUser ) {
      const { team } = user;
      const confirmLink = `${process.env.FRONTEND_URL}/${page}?tempToken=${tempToken}`;
      const htmlEmail
        = page === 'confirm'
          ? confirmationEmail( confirmLink, team.name )
          : passwordResetEmail( body, confirmLink, link );
      const params = setSesParams( user.email, htmlEmail, subject );

      await sendSesEmail( params );
    }

    return {
      text: reply,
    };
  } catch ( err ) {
    throw new ApolloError( err ); // debugging
    // throw new ApolloError( 'There is already a user with that email in the system.' );
  }
},