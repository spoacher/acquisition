import bcrypt from 'bcrypt';
import logger from '#config/logger.js';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { eq } from 'drizzle-orm';

export const hashPassword = async (password) => {
  try{
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);

  } catch(err){
    logger.error('Password hashing error:', err);
    throw new Error('Password hashing failed');
  }

};

export const createUser = async ({name, email, password, role='user'}) => {
  try{
    const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if(existingUser.length > 0) throw new Error('User with this email already exists');

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({name,email,password:password_hash,role})
      .returning({id: users.id, name: users.name, email: users.email, role: users.role, created_at: users.created_at});
    logger.info(`User created: ${email}`);
    return newUser;
  } catch(err){
    logger.error('User creation error:', err);
    throw err;
  }
};
export const comparePassword = async (password, hash) => {
  try{
    return await bcrypt.compare(password, hash);
  } catch(err){
    logger.error('Error comparing password :', err);
    throw new Error('Error comparing password: ' + err.message);
  }
};  

export const authenticateUser = async ({email, password}) => {
  try{
    const [existingUser] = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if(!existingUser) throw new Error('User not found');

    const isPasswordValid = await comparePassword(password, existingUser.password);

    if(!isPasswordValid) throw new Error('Invalid password');

    logger.info(`User authenticated: ${email}`);

    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
      created_at: existingUser.created_at
    };
  } catch(err){
    logger.error('Authentication error:', err);
    throw err;
  }
};