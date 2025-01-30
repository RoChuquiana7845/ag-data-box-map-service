import { Test, TestingModule } from '@nestjs/testing';
import { ClassificationLevelService } from './classification-level.service';

describe('ClassificationLevelService', () => {
  let service: ClassificationLevelService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ClassificationLevelService],
    }).compile();

    service = module.get<ClassificationLevelService>(
      ClassificationLevelService,
    );
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
