import logger from '#config/logger.js';
import { signupSchema, signinSchema } from '#validations/auth.validation.js';
import { formatValidationError } from '#utils/format.js';
import { createUser, authenticateUser } from '#services/auth.service.js';
import {jwttoken} from '#utils/jwt.js';
import {cookies} from '#utils/cookies.js';

export const signup = async (req, res, next) => {
  // Signup logic here
  try{
    const validationResult = signupSchema.safeParse(req.body);
    if(!validationResult.success){
      const formattedError = formatValidationError(validationResult.error);
      return res.status(400).json({ 
        error: 'Validation Failed',
        details: formattedError 
      });
    }
    const { name, email, password, role } = validationResult.data;

    // AUTH SERVICE CALL TO CREATE USER
    const user = await createUser({name, email, password, role});

    const token = jwttoken.sign({ id: user.id, email: user.email, role: user.role });

    cookies.set(res, 'token', token);

    logger.info(`User signed up: ${email}`);
    return res.status(201).json({ 
      message: 'User created successfully',
      user: { id:user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch(err){
    logger.error('Signup error:', err);

    if(err.message === 'User with this email already exists'){
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    next(err);
  }
};

export const signin = async (req, res, next) => {
  // Signin logic here
  try{
    const validationResult = signinSchema.safeParse(req.body);
    if(!validationResult.success){
      const formattedError = formatValidationError(validationResult.error);
      return res.status(400).json({ 
        error: 'Validation Failed',
        details: formattedError 
      });
    }
    const { email, password } = validationResult.data;
        
    // AUTH SERVICE CALL TO AUTHENTICATE USER
    const user = await authenticateUser({email, password});
    const token = jwttoken.sign({ id: user.id, email: user.email, role: user.role });
        
    cookies.set(res, 'token', token);
        
    logger.info(`User signed in: ${email}`);
    return res.status(200).json({ 
      message: 'User signed in successfully',
      user: { id:user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch(err){
    logger.error('Signin error:', err);
    if(err.message === 'Invalid password' || err.message === 'User not found'){
      return res.status(409).json({ status: 'failed', error: 'Invalid email or password' });
    }
    next(err);
  }
};

export const signout = (req, res, next) => {
  try{
    cookies.clear(res, 'token');
    logger.info('User signed out');
    return res.status(200).json({ message: 'User signed out successfully' });
  } catch(err){
    logger.error('Signout error:', err);
    next(err);
  }
};