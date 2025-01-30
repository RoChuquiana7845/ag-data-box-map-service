import { Test, TestingModule } from '@nestjs/testing';
import { ClassificationLevelController } from './classification-level.controller';

describe('ClassificationLevelController', () => {
  let controller: ClassificationLevelController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ClassificationLevelController],
    }).compile();

    controller = module.get<ClassificationLevelController>(
      ClassificationLevelController,
    );
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
