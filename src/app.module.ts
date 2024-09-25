import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtGuard } from './auth/guard';
import config from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, load: [config] }),
    AuthModule,
    UsersModule,
    PrismaModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: JwtGuard,
    },
  ],
})
export class AppModule {}
