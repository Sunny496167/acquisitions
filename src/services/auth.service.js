import { db } from '#config/database.js';
import logger from '#config/logger.js';
import { users } from '#models/user.models.js';
import bcrypt from 'bcrypt';
import { eq } from 'drizzle-orm';

export const hashPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error(`Error hashing password: ${e}`);
    throw new Error('Password hashing failed');
  }
};

export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if (existingUser.length > 0) {
      throw new Error('User already exists');
    }

    const hashedPassword = await hashPassword(password);

    const [newUser] = await db.insert(users).values({
      name,
      email,
      password: hashedPassword,
      role
    }).returning({
      id: users.id,
      name: users.name,
      email: users.email,
      role: users.role,
      created_at: users.created_at,
    });

    logger.info(`User ${newUser.email} created successfully`);
    return newUser;

  } catch (error) {
    logger.error(`Error creating user: ${error}`);
    throw new Error('User creation failed');
  }
};
