import { Module } from '@nestjs/common';
import { AreaController } from './area.controller';
import { AreaService } from './area.service';
import { Area } from './entities/area.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ProjectModule } from 'src/project/project.module';

@Module({
  imports: [TypeOrmModule.forFeature([Area]), ProjectModule],
  controllers: [AreaController],
  providers: [AreaService, TypeOrmModule],
})
export class AreaModule {}
