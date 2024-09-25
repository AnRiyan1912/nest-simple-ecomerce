import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtAtStrategy, JwtRtStrategy } from './strategy';
import { PrismaService } from 'src/prisma/prisma.service';

@Module({
  imports: [JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService, JwtRtStrategy, JwtAtStrategy, PrismaService],
})
export class AuthModule {}
