import { verifyGoogleToken } from '../../services/googleAuth';

const COOKIE_MAX_AGE = 1000 * 60 * 60 * 24 * 7; // 1 week, matches CloudFlare maxAge

// @deprecate - This should be handled on api server
const generateESCookie = ctx => {
  const esToken = jwt.sign( { user: process.env.ES_APP_USER }, process.env.ES_APP_SECRET );

  ctx.res.cookie( 'ES_TOKEN', esToken, {
    maxAge: COOKIE_MAX_AGE,
    secure: !process.env.NODE_ENV === 'development',
  } );
};

/**
 * @param {object} args { token } google tokenId
 */
  async googleSignin( parent, { token }, ctx ) {
  // 1. Was a google token sent?
  if ( !token ) {
    throw new AuthenticationError( 'A valid Google token is not available' );
  }

  // 2. Verify that the google token sent is valid
  const googleUser = await verifyGoogleToken( token );

  if ( !googleUser ) {
    throw new AuthenticationError( 'Unable to verify Google Token' );
  }

  // 3. Verify that the google token sent is within the america.gov domain
  if ( googleUser.hd !== 'america.gov' ) {
    throw new AuthenticationError(
      'You must first register using your america.gov email account to sign in.',
    );
  }

  if ( ENFORCE_WHITELIST ) {
    const whitelisted = await isEmailWhitelisted( googleUser.email );

    if ( !whitelisted ) {
      throw new AuthenticationError(
        'This america.gov account is not currently approved during our beta testing period.',
      );
    }
  }

  // 4. Check to see if user is in the db
  const user = await ctx.prisma.user.findUnique( {
    where: {
      email: googleUser.email,
    },
  } );

  if ( !user ) {
    throw new AuthenticationError(
      'You must first register your account before you can sign in.',
    );
  }

  if ( !user.isConfirmed ) {
    throw new AuthenticationError( 'You must confirm your account before you can sign in.' );
  }

  // 5.Create user's JWT token
  const jwtToken = await generateToken( user.id );

  // 6.Set the jwt as a cookie on the response
  setCookie( ctx, jwtToken );

  // 7. Set the ES token for client to ES communication
  // We should be getting tokens from api server
  // Since api is not yet ready to generate tokens so doing it here
  generateESCookie( ctx );

  // 8.Return user
  return user;
},