import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './user.schema';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { JwtModule } from '@nestjs/jwt'; 
import { JwtAuthGuard } from '../auth/jwt-auth.guard'; 

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    JwtModule.register({
      secret: process.env.JWT_SECRET,  // Ensure this is available in your .env file
      signOptions: { expiresIn: '1h' },  // Set expiration time as needed
    }),
  ],
  controllers: [UserController],
  providers: [UserService, JwtAuthGuard],  // Don't forget to add JwtAuthGuard if used
  exports: [UserService],
})
export class UserModule {}
