import { Module } from '@nestjs/common';
import { ClassificationLevelController } from './classification-level.controller';
import { ClassificationLevelService } from './classification-level.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ClassificationLevel } from './entities/classification-level.entity';

@Module({
  imports: [TypeOrmModule.forFeature([ClassificationLevel])],
  controllers: [ClassificationLevelController],
  providers: [ClassificationLevelService],
  exports: [ClassificationLevelService],
})
export class ClassificationLevelModule {}
