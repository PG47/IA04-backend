import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { JwtStrategy } from './auth/jwt.strategy';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }), // Global config module
    MongooseModule.forRoot(process.env.DATABASE_URI), // MongoDB connection
    UserModule, // User module
    AuthModule, // Authentication module
    JwtModule.register({
      secret: process.env.JWT_SECRET, // JWT secret from .env
      signOptions: { expiresIn: '1h' }, // Token expiration time
    }),
  ],
  providers: [JwtStrategy], // Register JwtStrategy as a provider here
})
export class AppModule {}
