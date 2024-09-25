import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { PrismaService } from 'src/prisma/prisma.service';

@Module({
  providers: [UsersService],
})
export class UsersModule {}
