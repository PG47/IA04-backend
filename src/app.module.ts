import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';  // Import ConfigModule
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { JwtStrategy } from './auth/jwt.strategy';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),  
    MongooseModule.forRoot(process.env.DATABASE_URI), 
    UserModule, 
    AuthModule, 
    JwtModule.register({
      secret: process.env.JWT_SECRET || "f3e2a0170ffcb8f39edcd16f4ad34ae636fd1f9df49e75934bd952a5fef6acf6",
      signOptions: { expiresIn: '12h' },     
    }),
  ],
})
export class AppModule {}
