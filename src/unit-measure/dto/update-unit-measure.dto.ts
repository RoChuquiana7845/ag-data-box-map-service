import { PartialType } from '@nestjs/mapped-types';
import { CreateUnitMeasureDto } from './create-unit-measure.dto';

export class UpdateUnitMeasureDto extends PartialType(CreateUnitMeasureDto) {}
